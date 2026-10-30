import { parse, store } from "../support/timestamps.js";

/**
 * Rétention GFS — jumelle de `GfsRetention` et `RetentionPlanner`.
 *
 * Étiquetage à la date d'achèvement (UTC) : toute sauvegarde est `daily` (7 j), un
 * dimanche ajoute `weekly` (28 j), le 1er du mois `monthly` (365 j), le 1er janvier
 * `yearly` (jamais par date). L'élagage garde l'union des 7 / 4 / 12 / 1 plus récentes
 * par palier, dans un horizon de 24 mois dont l'annuelle est exemptée.
 */

/** @param {Date} date */
export function tagFor(date) {
  const tags = ["daily"];
  let days = 7;
  if (date.getUTCDay() === 0) {
    tags.push("weekly");
    days = 28;
  }
  if (date.getUTCDate() === 1) {
    tags.push("monthly");
    days = 365;
  }
  if (date.getUTCDate() === 1 && date.getUTCMonth() === 0) {
    tags.push("yearly");
    days = null;
  }
  return {
    tag: tags.join(","),
    expires_at: days === null ? null : store(new Date(date.getTime() + days * 86_400_000)),
  };
}

/**
 * @param {{id: number, tags: string[], at: Date}[]} backups
 * @param {Date} now
 * @returns {{keep: number[], prune: number[]}}
 */
export function plan(backups, now, limits = { daily: 7, weekly: 4, monthly: 12, yearly: 1 }, horizonMonths = 24) {
  const sorted = [...backups].sort((a, b) => b.at.getTime() - a.at.getTime());
  const horizon = new Date(now);
  horizon.setUTCMonth(horizon.getUTCMonth() - horizonMonths);

  const keep = new Set();
  for (const [tier, limit] of Object.entries(limits)) {
    let kept = 0;
    for (const b of sorted) {
      if (kept >= limit) {
        break;
      }
      if (tier !== "daily" && !b.tags.includes(tier)) {
        continue;
      }
      if (tier !== "yearly" && b.at < horizon) {
        continue;
      }
      keep.add(b.id);
      kept++;
    }
  }
  return { keep: [...keep], prune: sorted.filter((b) => !keep.has(b.id)).map((b) => b.id) };
}

/**
 * Élague ce que le plan écarte : l'objet distant D'ABORD, la ligne ensuite — et la ligne
 * reste si le dépôt refuse, sinon on paierait un orphelin que plus rien ne nomme.
 *
 * @param {import("../state/repositories.js").BackupRepository} backups
 * @param {() => Promise<import("../storage/s3.js").ObjectStorage|null>} storage
 * @param {import("../logging.js").Logger} logger
 */
export async function cleanExpired(backups, storage, logger, now = new Date()) {
  const rows = backups.listRetainable();
  const candidates = rows
    .map((r) => ({ id: r.id, tags: String(r.retention_tag ?? "daily").split(",").filter(Boolean), at: parse(r.completed_at) }))
    .filter((c) => c.at !== null);
  if (candidates.length === 0) {
    return [];
  }
  const { prune } = plan(candidates, now);
  const pruned = [];
  const client = prune.length > 0 ? await storage() : null;
  for (const id of prune) {
    const row = backups.find(id);
    if (!row) {
      continue;
    }
    if (row.cloud_path) {
      if (client === null || !(await client.delete(row.cloud_path))) {
        logger.warning("backup", `Rétention GFS : objet distant non supprimé pour le backup #${id} (${row.cloud_path}) — ligne conservée, nouvel essai au prochain passage`);
        continue;
      }
    }
    backups.remove(id);
    pruned.push(id);
    logger.info("backup", `Rétention GFS : backup #${id} élagué`);
  }
  return pruned;
}
