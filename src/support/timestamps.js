/**
 * La convention d'horodatage de l'agent — jumelle de `AgentCore\Support\Timestamps`.
 *
 * Stockage : `AAAA-MM-JJ HH:MM:SS` en UTC. Fil : ISO 8601 avec un décalage EXPLICITE
 * (`2026-08-08T03:00:03+00:00`, le format `c` de PHP). Une heure murale sans décalage
 * est lue par le backend comme son heure locale et atterrit à des heures de l'instant réel.
 */

const pad = (n) => String(n).padStart(2, "0");

/** @param {Date} [date] */
export function store(date = new Date()) {
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`
  );
}

/** @param {string|null|undefined} stored */
export function parse(stored) {
  if (stored === null || stored === undefined || String(stored).trim() === "" || String(stored).startsWith("0000-00-00")) {
    return null;
  }
  const m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(String(stored));
  const date = m
    ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]))
    : new Date(String(stored));
  return Number.isNaN(date.getTime()) ? null : date;
}

/** ISO 8601, UTC, décalage explicite — jamais de millisecondes ni de `Z`, comme PHP. */
export function iso(date = new Date()) {
  return store(date).replace(" ", "T") + "+00:00";
}

/** @param {string|null|undefined} stored */
export function wire(stored) {
  const date = parse(stored);
  return date === null ? null : iso(date);
}

/** @param {string|null|undefined} stored */
export function toUnix(stored) {
  const date = parse(stored);
  return date === null ? null : Math.floor(date.getTime() / 1000);
}

/** Durée entière en secondes, ou `null` si l'une des bornes manque. */
export function durationSeconds(from, to) {
  const start = toUnix(from);
  const end = toUnix(to);
  return start === null || end === null ? null : end - start;
}

/** Heure locale du serveur, pour les journaux (`[AAAA-MM-JJ HH:MM:SS]`, comme FileLogger). */
export function local(date = new Date()) {
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  );
}

/** Jour local `AAAA-MM-JJ`, qui nomme le fichier de journal. */
export function localDay(date = new Date()) {
  return local(date).slice(0, 10);
}
