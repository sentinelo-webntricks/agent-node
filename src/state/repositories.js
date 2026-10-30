import { Collection } from "./collection.js";
import { parse, store } from "../support/timestamps.js";

/**
 * Les « tables » de l'agent, avec les requêtes dont le routeur et les runners ont besoin —
 * jumelles de `PdoBackupRepository`, `PdoRestoreRepository`, `PdoScanRepository`.
 */

const IN_PROGRESS = ["pending", "in_progress", "uploading"];

export class BackupRepository extends Collection {
  constructor(dataDir) {
    super(dataDir, "backups");
  }

  findInProgressId() {
    const row = this.all().filter((r) => IN_PROGRESS.includes(r.status)).sort((a, b) => b.id - a.id)[0];
    return row ? row.id : null;
  }

  /** La plus récente, hors des types écartés (les sauvegardes de sécurité, en général). */
  findLatest(excludeTypes = []) {
    return this.all().filter((r) => !excludeTypes.includes(r.backup_type)).sort((a, b) => b.id - a.id)[0] ?? null;
  }

  /** Une ligne « en cours » depuis plus de 30 min est celle d'un processus mort. */
  cancelStaleInProgress(minutes = 30, live = new Set()) {
    const limit = Date.now() - minutes * 60_000;
    for (const row of this.all()) {
      const started = parse(row.started_at);
      if (IN_PROGRESS.includes(row.status) && !live.has(row.id) && started !== null && started.getTime() < limit) {
        this.update(row.id, (r) => {
          r.status = "failed";
          r.completed_at = store();
          r.error_message = r.error_message ?? `Interrompue : aucun signe de vie depuis plus de ${minutes} minutes (agent redémarré ?).`;
        });
      }
    }
  }

  statistics() {
    const now = Date.now();
    const rows = this.all();
    const age = (r) => now - (parse(r.created_at)?.getTime() ?? now);
    const completed = rows.filter((r) => r.status === "completed");
    const oldest = rows.map((r) => r.created_at).filter(Boolean).sort()[0] ?? null;
    return {
      last_7_days: rows.filter((r) => age(r) <= 7 * 86_400_000).length,
      last_30_days: rows.filter((r) => age(r) <= 30 * 86_400_000).length,
      total_stored: completed.length,
      total_size_bytes: completed.reduce((sum, r) => sum + (Number(r.file_size_bytes) || 0), 0),
      oldest_backup: oldest,
    };
  }

  /** Ce que la rétention peut élaguer : terminées, ni manuelles ni de sécurité. */
  listRetainable() {
    return this.all().filter((r) => r.status === "completed" && !["manual", "safety"].includes(r.backup_type));
  }

  appendStep(id, step) {
    this.update(id, (r) => {
      r.steps = [...(r.steps ?? []), step];
    });
  }
}

export class RestoreRepository extends Collection {
  constructor(dataDir) {
    super(dataDir, "restores", { cap: 200 });
  }

  findInProgress() {
    return this.all().find((r) => r.status === "pending" || r.status === "in_progress") ?? null;
  }

  findLatest() {
    return this.all().sort((a, b) => b.id - a.id)[0] ?? null;
  }
}

export class ScanRepository extends Collection {
  constructor(dataDir) {
    super(dataDir, "scans", { cap: 200 });
  }

  findLatestTerminal() {
    return this.all().filter((r) => r.status === "completed" || r.status === "failed").sort((a, b) => b.id - a.id)[0] ?? null;
  }
}
