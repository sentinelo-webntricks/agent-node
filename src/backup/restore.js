import { copyFile, mkdir, readdir, rename, rm, stat } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { existsSync } from "node:fs";

import { decryptFile } from "../crypto/sntlo.js";
import { iso, store } from "../support/timestamps.js";
import { BaseBackupRequired } from "./errors.js";
import { RESTORE_SKIP, roles } from "./layout.js";
import { restorePayload } from "./payloads.js";
import { sha256File } from "./runner.js";
import { extract, readEntry, safeEntryPath } from "./tar.js";

/**
 * La restauration — jumelle de `AgentCore\Backup\RestoreRunner`.
 *
 * Dans cet ordre, et l'ordre est la garantie :
 *
 * 1. **sauvegarde de sécurité** du périmètre restauré — le seul retour possible si
 *    l'archive restaurée s'avère être la mauvaise ;
 * 2. **maintenance** posée (le proxy inverse rend 503 tant que le drapeau existe) ;
 * 3. **téléchargement** puis **empreinte SHA-256 vérifiée AVANT** de déchiffrer quoi que
 *    ce soit : on n'écrit rien sur le site depuis une archive qu'on n'a pas reconnue ;
 * 4. **base** importée, puis **fichiers** FUSIONNÉS (rien n'est effacé) ;
 * 5. maintenance levée — y compris sur échec.
 *
 * Ce qui ne bouge jamais : l'état de l'agent (clé, historique), qui vit hors du projet et
 * hors de la base — une restauration ne déconnecte donc jamais le site — ainsi que
 * `node_modules`, `.next`, `.git` et les `.env*`.
 */

const SCOPES = ["all", "db", "files"];

export class RestoreRunner {
  /** @param {import("../agent.js").Agent} agent */
  constructor(agent) {
    this.agent = agent;
  }

  /**
   * @param {{cloudPath: string, scope: string, safetyBackup: boolean, checksum: string|null, baseCloudPath: string|null, baseChecksum: string|null}} params
   * @returns {{id: number, done: Promise<void>}}
   */
  start(params) {
    const scope = SCOPES.includes(params.scope) ? params.scope : "all";
    const id = this.agent.restores.insert({
      source_cloud_path: params.cloudPath,
      scope,
      status: "in_progress",
      safety_backup_id: null,
      started_at: store(),
      completed_at: null,
      error_message: null,
      steps: [],
    });
    const done = this.run(id, { ...params, scope }).catch((e) => {
      this.agent.logger.error("restore", `Restauration #${id} : erreur hors du flux : ${e?.message ?? e}`);
    });
    return { id, done };
  }

  async run(id, params) {
    const { logger, restores, maintenance } = this.agent;
    const workDir = join(this.agent.settings.dataDir, "work", `restore-${id}`);
    const record = (step, status, message = null, startedAt = null) => {
      restores.update(id, (r) => {
        r.steps = [...(r.steps ?? []), { step, status, message, duration_ms: startedAt === null ? null : Math.round(Date.now() - startedAt), at: iso() }];
      });
    };
    const wantsDb = params.scope === "all" || params.scope === "db";
    const wantsFiles = params.scope === "all" || params.scope === "files";
    let maintenanceSet = false;

    logger.info("restore", `Restauration #${id} démarrée depuis ${params.cloudPath} (${params.scope})`);

    try {
      await mkdir(workDir, { recursive: true, mode: 0o700 });

      if (params.safetyBackup) {
        const t = Date.now();
        const includes = params.scope === "db" ? ["db"] : params.scope === "files" ? ["plugins", "themes", "uploads"] : ["db", "plugins", "themes", "uploads"];
        const safetyId = await this.agent.backupRunner.safety(includes, `Sauvegarde de sécurité avant restauration #${id}`);
        restores.update(id, { safety_backup_id: safetyId });
        record("safety_backup", "ok", `Backup #${safetyId}`, t);
      } else {
        record("safety_backup", "skipped", "Non demandée");
      }

      maintenance.enable();
      maintenanceSet = true;
      record("maintenance_on", "ok");

      const t3 = Date.now();
      const encrypted = params.cloudPath.endsWith(".enc");
      const downloaded = join(workDir, encrypted ? "backup.tar.enc" : "backup.tar");
      await this.agent.storage().get(params.cloudPath, downloaded);
      record("download", "ok", `${((await stat(downloaded)).size / 1048576).toFixed(1)} Mo`, t3);

      const t4 = Date.now();
      if (params.checksum) {
        const actual = await sha256File(downloaded);
        if (actual.toLowerCase() !== params.checksum.toLowerCase()) {
          throw new Error(`Empreinte SHA-256 différente de celle enregistrée à la sauvegarde (attendue ${params.checksum.slice(0, 12)}…, obtenue ${actual.slice(0, 12)}…) : archive altérée ou incomplète, rien n'a été écrit.`);
        }
        record("checksum", "ok", "Empreinte conforme", t4);
      } else {
        record("checksum", "skipped", "Aucune empreinte fournie");
      }

      const t5 = Date.now();
      let tarPath = downloaded;
      if (encrypted) {
        tarPath = join(workDir, "backup.tar");
        await decryptFile(this.agent.cryptoKey(), downloaded, tarPath);
        await rm(downloaded, { force: true });
      }
      const manifest = JSON.parse((await readEntry(tarPath, "manifest.json"))?.toString("utf8") ?? "{}");
      if (manifest.mode === "differential" && !params.baseCloudPath) {
        throw new BaseBackupRequired(`Sauvegarde différentielle : la sauvegarde de base #${manifest.base_backup_id ?? "?"} est requise (base_cloud_path).`);
      }
      const extracted = join(workDir, "extracted");
      const count = await extract(tarPath, extracted);
      await rm(tarPath, { force: true });
      record("extract", "ok", `${count} entrées`, t5);

      if (wantsDb) {
        const t6 = Date.now();
        const entry = manifest.db_entry ?? null;
        if (entry === null || !existsSync(join(extracted, entry))) {
          record("db_import", "skipped", "L'archive ne contient pas de base.");
        } else {
          const database = this.agent.database();
          if (database === null) {
            throw new Error("L'archive contient une base, mais aucune base n'est configurée ici (DATABASE_URL absent).");
          }
          if (manifest.db_engine && manifest.db_engine !== database.engine) {
            throw new Error(`L'archive contient une base ${manifest.db_engine}, la base configurée est ${database.engine} : restauration refusée.`);
          }
          await database.restore(join(extracted, entry), workDir);
          record("db_import", "ok", database.engine, t6);
        }
      }

      if (wantsFiles) {
        const t7 = Date.now();
        const restored = await this.restoreFiles(join(extracted, "files"));
        record("files_restore", "ok", `${restored} fichiers`, t7);
      }

      maintenance.disable();
      maintenanceSet = false;
      record("maintenance_off", "ok");

      restores.update(id, { status: "completed", completed_at: store() });
      record("completed", "ok");
      logger.info("restore", `Restauration #${id} terminée`);
      await this.agent.webhooks.send("restore.completed", restorePayload(restores.find(id)));
    } catch (e) {
      const message = String(e?.message ?? e);
      logger.error("restore", `Restauration #${id} échouée : ${message}`);
      if (maintenanceSet) {
        try {
          maintenance.disable();
        } catch {
          // Le drapeau reste : le journal le dit, l'opérateur le lève à la main.
        }
      }
      restores.update(id, (r) => {
        r.status = "failed";
        r.completed_at = store();
        r.error_message = message;
        r.steps = [...(r.steps ?? []), { step: "failed", status: "failed", message, duration_ms: null, at: iso() }];
      });
      await this.agent.webhooks.send("restore.failed", { ...restorePayload(restores.find(id)), error: message });
    } finally {
      await rm(workDir, { recursive: true, force: true });
    }
  }

  /** Fusionne `files/<rôle>/…` dans les répertoires actuels. Rien n'est effacé. */
  async restoreFiles(filesRoot) {
    if (!existsSync(filesRoot)) {
      return 0;
    }
    const byPrefix = new Map(roles(this.agent.settings).map((r) => [r.prefix.replace(/^files\//, "").replace(/\/$/, ""), r]));
    const dataDir = this.agent.settings.dataDir;
    let count = 0;

    for (const roleDir of await readdir(filesRoot)) {
      const role = byPrefix.get(roleDir);
      if (!role || !role.dir) {
        this.agent.logger.warning("restore", `Contenu « ${roleDir} » de l'archive sans destination sur ce serveur : ignoré.`);
        continue;
      }
      const base = join(filesRoot, roleDir);
      const walk = async (dir) => {
        for (const name of await readdir(dir, { withFileTypes: true })) {
          const from = join(dir, name.name);
          const rel = relative(base, from).split(sep).join("/");
          if (RESTORE_SKIP.some((re) => re.test(rel))) {
            continue;
          }
          if (name.isDirectory()) {
            await walk(from);
            continue;
          }
          const to = safeEntryPath(role.dir, rel);
          if (to === dataDir || to.startsWith(dataDir + sep)) {
            continue;
          }
          await mkdir(dirname(to), { recursive: true });
          // À côté puis renommé : un visiteur voit l'ancienne version ou la nouvelle,
          // jamais un fichier à moitié écrit.
          const tmp = `${to}.sentinelo-restore`;
          await copyFile(from, tmp);
          await rename(tmp, to);
          count++;
        }
      };
      await walk(base);
    }
    return count;
  }
}
