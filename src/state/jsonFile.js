import { closeSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Un fichier JSON lu et réécrit en entier, ATOMIQUEMENT et SOUS VERROU.
 *
 * Deux processus touchent l'état : le démon (`serve`) et une commande lancée à la main
 * (`enroll`, `run`, `status`). Une lecture-modification-écriture sans verrou perd la
 * modification de l'un des deux ; une écriture sans renommage laisse, sur un processus
 * tué, un fichier à moitié écrit qu'aucune lecture suivante ne sait relire.
 *
 * Le verrou est un fichier créé en exclusif (`wx`) — portable, sans dépendance. Un verrou
 * plus vieux que `STALE_MS` est celui d'un processus mort et se reprend : sinon un seul
 * arrêt brutal bloquerait l'agent pour toujours.
 */

const STALE_MS = 30_000;
const WAIT_MS = 10_000;

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function acquire(lockPath) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    try {
      closeSync(openSync(lockPath, "wx"));
      return;
    } catch (e) {
      if (e.code !== "EEXIST") {
        throw e;
      }
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > STALE_MS) {
          unlinkSync(lockPath);
          continue;
        }
      } catch {
        continue;
      }
      if (Date.now() > deadline) {
        throw new Error(`Verrou ${lockPath} tenu depuis plus de ${WAIT_MS / 1000} s.`);
      }
      sleepSync(25);
    }
  }
}

function release(lockPath) {
  try {
    unlinkSync(lockPath);
  } catch {
    // Déjà repris comme périmé par un autre processus : rien à faire.
  }
}

/** @template T @param {string} path @param {T} fallback @returns {T} */
export function readJson(path, fallback) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    if (e.code === "ENOENT") {
      return fallback;
    }
    throw new Error(`État illisible (${path}) : ${e.message}`);
  }
}

export function writeJsonAtomic(path, value, mode = 0o600) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(value, null, 2), { mode });
  renameSync(tmp, path);
}

/**
 * Lit, applique `mutate`, réécrit — le tout sous verrou. `mutate` reçoit la valeur et la
 * rend (ou la modifie en place) ; ce qu'il rend en second élément est retourné à l'appelant.
 *
 * @template T, R
 * @param {string} path
 * @param {T} fallback
 * @param {(value: T) => R} mutate
 * @returns {R}
 */
export function updateJson(path, fallback, mutate) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const lockPath = `${path}.lock`;
  acquire(lockPath);
  try {
    const value = readJson(path, structuredClone(fallback));
    const result = mutate(value);
    writeJsonAtomic(path, value);
    return result;
  } finally {
    release(lockPath);
  }
}
