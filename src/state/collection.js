import { join } from "node:path";

import { readJson, updateJson } from "./jsonFile.js";

/**
 * Une table minimale dans un fichier JSON : identifiants entiers croissants, lignes
 * plates aux noms de colonnes des agents PHP.
 *
 * Les identifiants sont des ENTIERS POSITIFS parce que le contrat l'exige : le backend
 * corrèle par `wpBackupId` / `wpScanId` et refuse tout le reste. Les noms de colonnes sont
 * ceux de `Schema.php` (agent Composer) pour que les constructeurs de payload se lisent
 * côte à côte avec leurs jumeaux PHP.
 */
export class Collection {
  /** @param {string} dataDir @param {string} name @param {{cap?: number}} [options] */
  constructor(dataDir, name, options = {}) {
    this.path = join(dataDir, "state", `${name}.json`);
    this.cap = options.cap ?? null;
  }

  all() {
    return readJson(this.path, { next_id: 1, rows: [] }).rows;
  }

  /** @param {number} id */
  find(id) {
    return this.all().find((row) => row.id === id) ?? null;
  }

  /** @param {(row: any) => boolean} predicate */
  filter(predicate) {
    return this.all().filter(predicate);
  }

  /** Insère et rend l'identifiant attribué. */
  insert(row) {
    return updateJson(this.path, { next_id: 1, rows: [] }, (table) => {
      const id = table.next_id++;
      table.rows.push({ ...row, id });
      // Plafond : un historique de scans hebdomadaires grossirait sans fin. On garde les
      // plus récents ; les sauvegardes, elles, ont leur propre rétention et pas de plafond.
      if (this.cap !== null && table.rows.length > this.cap) {
        table.rows.splice(0, table.rows.length - this.cap);
      }
      return id;
    });
  }

  /** @param {number} id @param {Record<string, unknown>|((row: any) => void)} patch */
  update(id, patch) {
    return updateJson(this.path, { next_id: 1, rows: [] }, (table) => {
      const row = table.rows.find((r) => r.id === id);
      if (!row) {
        return false;
      }
      if (typeof patch === "function") {
        patch(row);
      } else {
        Object.assign(row, patch);
      }
      return true;
    });
  }

  /** @param {number} id */
  remove(id) {
    return updateJson(this.path, { next_id: 1, rows: [] }, (table) => {
      const before = table.rows.length;
      table.rows = table.rows.filter((r) => r.id !== id);
      return table.rows.length !== before;
    });
  }

  /** @param {(row: any) => boolean} predicate */
  removeWhere(predicate) {
    return updateJson(this.path, { next_id: 1, rows: [] }, (table) => {
      const before = table.rows.length;
      table.rows = table.rows.filter((r) => !predicate(r));
      return before - table.rows.length;
    });
  }
}
