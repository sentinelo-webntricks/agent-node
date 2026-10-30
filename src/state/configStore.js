import { join } from "node:path";

import { decryptString, encryptString } from "../crypto/sntlo.js";
import { readJson, updateJson } from "./jsonFile.js";

/**
 * La configuration de l'agent — jumelle de `TableConfigStore` (agent Composer).
 *
 * Mêmes clés, même partage : `api_key`, `webhook_secret` et `cloud_credentials` sont
 * chiffrés au repos avec la clé dérivée du secret ; le reste (`saas_url`, `site_uuid`,
 * `connected_at`, `cloud_provider`…) est en clair. Un secret qu'on ne sait plus ouvrir —
 * secret changé, fichier altéré — se lit comme ABSENT, exactement comme côté PHP : l'agent
 * répond alors `NOT_CONFIGURED`, ce qui nomme le remède (réenrôler) au lieu d'un 500.
 */

export const SECRET_KEYS = ["api_key", "webhook_secret", "cloud_credentials"];

export class ConfigStore {
  /**
   * @param {string} dataDir
   * @param {() => Buffer} keyProvider dérivation paresseuse : un agent sans secret doit
   *        pouvoir démarrer et répondre `NOT_CONFIGURED`, pas mourir au chargement.
   */
  constructor(dataDir, keyProvider) {
    this.path = join(dataDir, "config.json");
    this.keyProvider = keyProvider;
  }

  /** @param {string} name */
  get(name, fallback = null) {
    const entry = readJson(this.path, {})[name];
    if (entry === undefined || entry === null) {
      return fallback;
    }
    if (!entry.secret) {
      return entry.value ?? fallback;
    }
    try {
      return JSON.parse(decryptString(this.keyProvider(), entry.value));
    } catch {
      return fallback;
    }
  }

  /** @param {string} name @param {unknown} value `null` efface la clé */
  set(name, value) {
    const secret = SECRET_KEYS.includes(name);
    // Chiffré AVANT de prendre le verrou : une dérivation qui échoue ne doit rien écrire.
    const stored = value === null || value === undefined ? null : secret ? encryptString(this.keyProvider(), JSON.stringify(value)) : value;
    updateJson(this.path, {}, (all) => {
      if (stored === null) {
        delete all[name];
      } else {
        all[name] = { value: stored, secret, updated_at: new Date().toISOString() };
      }
    });
  }

  delete(name) {
    this.set(name, null);
  }
}
