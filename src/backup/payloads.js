import { durationSeconds, wire } from "../support/timestamps.js";

/**
 * Les payloads de sauvegarde et de restauration — jumeaux de `BackupPayload` et
 * `RestorePayload`. Les mêmes clés servent la route de statut ET le webhook : la
 * plateforme corrèle les deux, et une divergence ne se verrait qu'une fois sur deux.
 */

const toMb = (bytes) => (bytes === null ? null : Math.round((bytes / 1048576) * 100) / 100);

const intOrNull = (value) => (value === null || value === undefined || value === "" ? null : Number(value));

/** @param {any} row ligne de la collection `backups` */
export function backupPayload(row) {
  const fileBytes = intOrNull(row.file_size_bytes);
  const dbBytes = intOrNull(row.db_size_bytes);
  return {
    backup_id: intOrNull(row.id),
    type: row.backup_type ?? null,
    backup_type: row.backup_type ?? null,
    status: row.status ?? null,
    started_at: wire(row.started_at),
    completed_at: wire(row.completed_at),
    duration_seconds: durationSeconds(row.started_at, row.completed_at),
    file_size_bytes: fileBytes,
    db_size_bytes: dbBytes,
    file_size_mb: toMb(fileBytes),
    db_size_mb: toMb(dbBytes),
    size_mb: toMb(fileBytes),
    cloud_provider: row.cloud_provider ?? null,
    cloud_bucket: row.cloud_bucket ?? null,
    cloud_path: row.cloud_path ?? null,
    cloud_url: row.cloud_url ?? null,
    checksum_sha256: row.checksum_sha256 ?? null,
    checksum: row.checksum_sha256 ?? null,
    error_message: row.error_message ?? null,
    retention_tag: row.retention_tag ?? null,
    expires_at: wire(row.expires_at),
    includes: [row.includes_db ? "db" : null, row.includes_files ? "files" : null, row.includes_uploads ? "uploads" : null].filter(Boolean),
    steps: row.steps ?? [],
    mode: row.mode ?? "full",
    base_backup_id: intOrNull(row.base_backup_id),
  };
}

/** @param {any} row ligne de la collection `restores` */
export function restorePayload(row) {
  return {
    restore_id: intOrNull(row.id),
    scope: row.scope ?? null,
    status: row.status ?? null,
    started_at: wire(row.started_at),
    completed_at: wire(row.completed_at),
    duration_seconds: durationSeconds(row.started_at, row.completed_at),
    safety_backup_id: intOrNull(row.safety_backup_id),
    error_message: row.error_message ?? null,
    source_cloud_path: row.source_cloud_path ?? null,
    steps: row.steps ?? [],
  };
}
