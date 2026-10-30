import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readdir, rename, rm, statfs, stat } from "node:fs/promises";
import { join } from "node:path";

import { encryptFile } from "../crypto/sntlo.js";
import { iso, store } from "../support/timestamps.js";
import { AGENT_VERSION } from "../version.js";
import { fileSize } from "./database.js";
import { BackupAlreadyRunning } from "./errors.js";
import { planFiles, roles } from "./layout.js";
import { backupPayload } from "./payloads.js";
import { cleanExpired, tagFor } from "./retention.js";
import { TarWriter } from "./tar.js";
import { StorageRefusal, TransientStorageFailure } from "../storage/s3.js";

/**
 * La sauvegarde — jumelle de `AgentCore\Backup\BackupRunner`, sans la mécanique de reprise.
 *
 * ## Pourquoi pas de reprise par passages
 *
 * L'agent PHP découpe archivage, chiffrement et envoi en passages de 120 s parce qu'un
 * hébergement mutualisé tue toute requête à 360 s. Un démon Node n'a pas cette limite : la
 * sauvegarde va d'un trait. Un redémarrage en plein travail laisse une ligne « en cours »
 * que {@link BackupRepository.cancelStaleInProgress} clôt en échec après 30 min, et le
 * dossier de travail est ramassé au démarrage suivant.
 *
 * ## Les étapes, et leurs noms sur le fil
 *
 * `db_dump` → `archive` → `encrypt` → `cloud_upload` → `verify` → `completed`, chacune
 * journalisée dans `steps` au moment où elle se termine : la plateforme montre ainsi la
 * phase en cours, et celle où ça a cassé.
 */

export const BACKUP_TYPES = ["daily", "weekly", "monthly", "yearly", "manual", "safety"];
export const LOCAL_ONLY_PREFIX = "Envoi cloud impossible, archive gardée sur le serveur du site — ";
const MIN_FREE_BYTES = 256 * 1024 * 1024;

export class BackupRunner {
  /** @param {import("../agent.js").Agent} agent */
  constructor(agent) {
    this.agent = agent;
    this.upload = null;
    /** @type {Set<number>} */
    this.abandoned = new Set();
    /** Les sauvegardes que CE processus est en train de faire. @type {Set<number>} */
    this.live = new Set();
  }

  get workRoot() {
    return join(this.agent.settings.dataDir, "work");
  }

  /**
   * Démarre une sauvegarde et rend la main tout de suite.
   *
   * @returns {{id: number, done: Promise<void>}}
   */
  start(options) {
    const type = String(options.type ?? "manual");
    // Validé ICI, avant toute écriture : un type inconnu laissait côté PHP une ligne en
    // échec et une erreur de base mal traduite (« lancez sentinelo:run »).
    if (!BACKUP_TYPES.includes(type)) {
      const error = new Error(`Type de sauvegarde inconnu : « ${type} ». Attendu : ${BACKUP_TYPES.join(", ")}.`);
      error.code = "VALIDATION_ERROR";
      throw error;
    }

    const backups = this.agent.backups;
    // Seules les lignes qu'AUCUN travail de ce démon ne porte sont périmées : une grosse
    // sauvegarde qui dure plus de 30 min est vivante, pas morte.
    backups.cancelStaleInProgress(30, this.live);
    const running = backups.findInProgressId();
    if (running !== null) {
      throw new BackupAlreadyRunning(running);
    }

    const includes = options.includes?.length ? options.includes : ["db", "plugins", "themes", "uploads"];
    const now = store();
    const id = backups.insert({
      backup_type: type,
      status: "in_progress",
      started_at: now,
      created_at: now,
      completed_at: null,
      includes_db: includes.includes("db"),
      includes_files: includes.includes("plugins") || includes.includes("themes"),
      includes_uploads: includes.includes("uploads"),
      mode: "full",
      base_backup_id: null,
      comment: options.comment || null,
      steps: [],
    });

    this.live.add(id);
    const done = this.run(id, { ...options, type, includes })
      .catch((e) => {
        this.agent.logger.error("backup", `Backup #${id} : erreur inattendue hors du flux : ${e?.message ?? e}`);
      })
      .finally(() => this.live.delete(id));
    return { id, done };
  }

  /** Sauvegarde de sécurité, attendue jusqu'au bout — la restauration en dépend. */
  async safety(includes, comment) {
    const { id, done } = this.start({ type: "safety", includes, cloud_upload: true, comment });
    await done;
    const row = this.agent.backups.find(id);
    if (row?.status !== "completed") {
      throw new Error(`Sauvegarde de sécurité #${id} non aboutie : ${row?.error_message ?? "raison inconnue"}`);
    }
    return id;
  }

  uploadState() {
    return this.upload;
  }

  abandon(id, reason) {
    const row = this.agent.backups.find(id);
    if (!row || !["pending", "in_progress", "uploading"].includes(row.status)) {
      return { backup_id: id, status: row?.status ?? "unknown", abandoned: false, staging_removed: false, upload_aborted: false };
    }
    this.abandoned.add(id);
    this.agent.backups.update(id, (r) => {
      r.status = "failed";
      r.completed_at = store();
      r.error_message = reason;
      r.steps = [...(r.steps ?? []), { step: "abandoned", status: "failed", message: reason, duration_ms: null, at: iso() }];
    });
    return { backup_id: id, status: "failed", abandoned: true, staging_removed: false, upload_aborted: false };
  }

  /** Les dossiers de travail d'exécutions mortes, hors archives gardées faute d'envoi. */
  async sweepOrphans() {
    let names = [];
    try {
      names = await readdir(this.workRoot);
    } catch {
      return;
    }
    const live = this.agent.backups.findInProgressId();
    for (const name of names) {
      if (name === "kept" || String(live) === name) {
        continue;
      }
      await rm(join(this.workRoot, name), { recursive: true, force: true });
    }
  }

  async run(id, options) {
    const { logger, backups } = this.agent;
    const workDir = join(this.workRoot, String(id));
    const record = (step, status, message = null, startedAt = null) => {
      backups.appendStep(id, { step, status, message, duration_ms: startedAt === null ? null : Math.round(Date.now() - startedAt), at: iso() });
    };
    const checkAbandoned = () => {
      if (this.abandoned.has(id)) {
        throw new Error("Abandonnée par la plateforme.");
      }
    };

    logger.info("backup", `Backup #${id} démarré (${options.type}, ${options.includes.join("+")})`);

    try {
      await mkdir(workDir, { recursive: true, mode: 0o700 });
      await this.assertFreeSpace(workDir, MIN_FREE_BYTES);

      // 1. La base.
      let dbBytes = 0;
      let dbEntry = null;
      let dbFile = null;
      const database = options.includes.includes("db") ? this.agent.database() : null;
      if (options.includes.includes("db")) {
        const t = Date.now();
        if (database === null) {
          backups.update(id, { includes_db: false });
          record("db_dump", "skipped", "Aucune base configurée (DATABASE_URL absent) : sauvegarde des fichiers seulement.", t);
        } else {
          dbFile = join(workDir, database.entry);
          await database.dump(dbFile, workDir);
          dbBytes = await fileSize(dbFile);
          dbEntry = database.entry;
          record("db_dump", "ok", `${database.engine} : ${(dbBytes / 1048576).toFixed(1)} Mo${database.lastWarning ? ` — ${database.lastWarning}` : ""}`, t);
          await this.assertFreeSpace(workDir, dbBytes * 3);
        }
      }
      checkAbandoned();

      // 2. L'archive : la base d'abord, les fichiers, le manifeste en dernier.
      const t2 = Date.now();
      const selected = roles(this.agent.settings).filter((r) => options.includes.includes(r.role));
      const plan = await planFiles(selected, [...this.agent.settings.excludePaths, ...(options.exclude_paths ?? [])]);
      const plannedBytes = plan.reduce((s, f) => s + f.size, 0);
      await this.assertFreeSpace(workDir, Math.ceil((plannedBytes + dbBytes) * 2.1));

      // `AAAA-MM-JJ-HHMMSS`, le `gmdate('Y-m-d-His')` de l'agent PHP.
      const stamp = store().replace(" ", "-").replace(/:/g, "");
      const siteUuid = String(this.agent.config.get("site_uuid") || "local");
      const baseName = `backup-${siteUuid}-${stamp}`;
      const tarPath = join(workDir, `${baseName}.tar`);
      const tar = new TarWriter(tarPath);
      try {
        if (dbFile !== null) {
          await tar.addFile(dbFile, dbEntry, dbBytes);
        }
        for (const file of plan) {
          checkAbandoned();
          try {
            await tar.addFile(file.source, file.entry, file.size);
          } catch (e) {
            // Disparu depuis le plan : sauté et signalé, comme côté PHP.
            logger.warning("backup", `Backup #${id} : ${file.entry} sauté (${e.code ?? e.message})`);
          }
        }
        await tar.addBuffer("manifest.json", JSON.stringify(this.manifest(id, options, database, plan.length), null, 4));
        await tar.seal();
      } catch (e) {
        await tar.abort();
        throw e;
      }
      record("archive", "ok", `${plan.length} fichiers, ${(plannedBytes / 1048576).toFixed(1)} Mo`, t2);
      if (dbFile !== null) {
        await rm(dbFile, { force: true });
      }
      checkAbandoned();

      // 3. Le chiffrement, puis l'empreinte DU FICHIER CHIFFRÉ — celle que la plateforme
      //    comparera avant toute restauration.
      const t3 = Date.now();
      const encPath = `${tarPath}.enc`;
      await encryptFile(this.agent.cryptoKey(), tarPath, encPath);
      await rm(tarPath, { force: true });
      const size = (await stat(encPath)).size;
      const checksum = await sha256File(encPath);
      record("encrypt", "ok", `${(size / 1048576).toFixed(1)} Mo chiffrés`, t3);
      checkAbandoned();

      const cloudPath = `backups/${siteUuid}/${options.type}/${baseName}.tar.enc`;
      const completion = { file_size_bytes: size, db_size_bytes: dbBytes, checksum_sha256: checksum, cloud_provider: null, cloud_bucket: null, cloud_path: null, cloud_url: null, error_message: null };

      // 4. L'envoi.
      if (options.cloud_upload !== false) {
        const t4 = Date.now();
        let storage;
        try {
          storage = this.agent.storage();
        } catch (e) {
          // Aucun identifiant : une configuration à faire, pas une panne passagère. La
          // sauvegarde échoue pour que le geste apparaisse.
          throw new Error(e instanceof StorageRefusal ? "Cloud credentials not configured" : e.message);
        }
        try {
          backups.update(id, { status: "uploading" });
          this.upload = { backup_id: id, completed_parts: 0, total_parts: 1, percent: 0, started_at: iso() };
          const result = await storage.put(encPath, cloudPath, (p) => {
            this.upload = { ...this.upload, ...p, percent: Math.round((p.completed_parts / p.total_parts) * 100) };
          });
          record("cloud_upload", "ok", `${cloudPath}`, t4);

          const t5 = Date.now();
          const remote = await storage.size(cloudPath);
          if (remote !== size) {
            throw new StorageRefusal(remote === null ? "objet absent du dépôt après envoi" : `taille distante ${remote} ≠ ${size} octets envoyés`);
          }
          record("verify", "ok", "Taille distante conforme", t5);
          Object.assign(completion, { cloud_provider: storage.provider, cloud_bucket: result.bucket, cloud_path: cloudPath, cloud_url: result.url });
          await rm(encPath, { force: true });
        } catch (e) {
          if (!(e instanceof StorageRefusal || e instanceof TransientStorageFailure)) {
            throw e;
          }
          // Le dépôt refuse ou se tait : la sauvegarde ABOUTIT quand même, gardée sur le
          // serveur — une archive construite et chiffrée ne se jette pas pour une tranche.
          const kept = await this.keepLocally(id, encPath);
          completion.error_message = `${LOCAL_ONLY_PREFIX}${e.message}`;
          record("local_copy", "ok", `Archive gardée : ${kept}`, t4);
          logger.warning("backup", `Backup #${id} gardé localement : ${e.message}`);
        } finally {
          this.upload = null;
        }
      } else {
        const kept = await this.keepLocally(id, encPath);
        record("local_copy", "ok", `Envoi désactivé — archive gardée : ${kept}`);
      }

      // 5. Clôture, étiquetage GFS, élagage.
      const completedAt = new Date();
      const { tag, expires_at } = tagFor(completedAt);
      backups.update(id, { ...completion, status: "completed", completed_at: store(completedAt), retention_tag: tag, expires_at });
      record("completed", "ok", null);
      logger.info("backup", `Backup #${id} terminé (${(size / 1048576).toFixed(1)} Mo, ${tag})`);

      try {
        await cleanExpired(backups, async () => {
          try {
            return this.agent.storage();
          } catch {
            return null;
          }
        }, logger);
      } catch (e) {
        logger.warning("backup", `Rétention : ${e.message}`);
      }

      await this.agent.webhooks.send("backup.completed", backupPayload(backups.find(id)));
    } catch (e) {
      const message = String(e?.message ?? e);
      logger.error("backup", `Backup #${id} échoué : ${message}`);
      if (!this.abandoned.has(id)) {
        backups.update(id, (r) => {
          r.status = "failed";
          r.completed_at = store();
          r.error_message = message;
          r.steps = [...(r.steps ?? []), { step: "failed", status: "failed", message, duration_ms: null, at: iso() }];
        });
        const row = backups.find(id);
        await this.agent.webhooks.send("backup.failed", { ...backupPayload(row), failed_at_step: lastStep(row) });
      }
    } finally {
      this.abandoned.delete(id);
      await rm(workDir, { recursive: true, force: true });
    }
  }

  manifest(id, options, database, fileCount) {
    const app = this.agent.application();
    return {
      backup_id: id,
      site_uuid: this.agent.config.get("site_uuid") ?? null,
      type: options.type,
      created_at: iso(),
      application: app.slug,
      application_version: app.version,
      php_version: null,
      runtime: "node",
      node_version: process.versions.node,
      db_name: database?.databaseName() ?? null,
      db_engine: database?.engine ?? null,
      db_entry: database?.entry ?? null,
      includes: options.includes,
      file_count: fileCount,
      comment: options.comment || null,
      plugins: [],
      active_theme: null,
      generator: `Sentinelo/${AGENT_VERSION}`,
      mode: "full",
    };
  }

  /** Une seule copie gardée au plus sur le disque du client : la suivante remplace. */
  async keepLocally(id, encPath) {
    const keptDir = join(this.workRoot, "kept");
    await rm(keptDir, { recursive: true, force: true });
    await mkdir(keptDir, { recursive: true, mode: 0o700 });
    const target = join(keptDir, `backup-${id}-${encPath.split(/[\\/]/).pop()}`);
    await rename(encPath, target);
    return target;
  }

  async assertFreeSpace(dir, needed) {
    try {
      const s = await statfs(dir);
      const free = Number(s.bavail) * Number(s.bsize);
      if (free < needed) {
        throw new Error(`Espace disque insuffisant : ${(free / 1048576).toFixed(0)} Mo libres, ${(needed / 1048576).toFixed(0)} Mo nécessaires.`);
      }
    } catch (e) {
      if (String(e.message).startsWith("Espace disque")) {
        throw e;
      }
      // Mesure refusée par le système : on tente quand même.
    }
  }
}

function lastStep(row) {
  const steps = (row?.steps ?? []).filter((s) => s.step !== "failed");
  return steps.length ? steps[steps.length - 1].step : null;
}

export function sha256File(path) {
  return new Promise((resolvePromise, reject) => {
    const hash = createHash("sha256");
    createReadStream(path)
      .on("data", (d) => hash.update(d))
      .on("end", () => resolvePromise(hash.digest("hex")))
      .on("error", reject);
  });
}
