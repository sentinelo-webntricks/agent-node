import { createHash, timingSafeEqual } from "node:crypto";

/**
 * L'authentification de chaque appel — jumelle de `AgentCore\Http\Authenticator`.
 *
 * Dans cet ordre : limite de débit (60 appels / 300 s par IP, fenêtre fixe), puis
 * `NOT_CONFIGURED` tant qu'aucune clé n'est enregistrée — un agent fraîchement installé
 * refuse tout le monde, À DESSEIN —, puis comparaison à temps constant de l'en-tête
 * `X-Sentinelo-API-Key`. Aucune route publique, pas même `health`.
 *
 * Le compteur vit en mémoire : l'agent est un démon unique, et un redémarrage qui le remet
 * à zéro coûte au pire une fenêtre de cinq minutes à un attaquant.
 */

const MAX_ATTEMPTS = 60;
const WINDOW_SECONDS = 300;

export class Authenticator {
  /** @param {import("../state/configStore.js").ConfigStore} config @param {import("../logging.js").Logger} logger */
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    /** @type {Map<string, {count: number, resetAt: number}>} */
    this.windows = new Map();
  }

  /**
   * @param {{ip: string, headers: Record<string, string|undefined>}} request
   * @returns {{code: string, message: string, status: number} | null}
   */
  authorise(request) {
    const now = Math.floor(Date.now() / 1000);
    const bucket = createHash("sha256").update(request.ip || "unknown").digest("hex").slice(0, 32);
    let window = this.windows.get(bucket);
    if (!window || window.resetAt <= now) {
      window = { count: 0, resetAt: now + WINDOW_SECONDS };
      this.windows.set(bucket, window);
    }
    window.count++;
    if (window.count > MAX_ATTEMPTS) {
      return { code: "TOO_MANY_REQUESTS", message: "Trop de requêtes. Réessayez plus tard.", status: 429 };
    }

    const stored = this.config.get("api_key");
    if (typeof stored !== "string" || stored === "") {
      return {
        code: "NOT_CONFIGURED",
        message: "Agent non enrôlé : aucune clé API n'est configurée sur ce site.",
        status: 403,
      };
    }

    const presented = request.headers["x-sentinelo-api-key"] ?? "";
    if (!equals(stored, presented)) {
      this.logger.warning("auth", `Clé API refusée depuis ${request.ip}`);
      return { code: "UNAUTHORIZED", message: "Clé API invalide ou absente.", status: 401 };
    }

    // Purge opportuniste : sans elle, la table grossirait d'une entrée par IP vue.
    if (this.windows.size > 10_000) {
      for (const [key, w] of this.windows) {
        if (w.resetAt <= now) {
          this.windows.delete(key);
        }
      }
    }
    return null;
  }
}

function equals(a, b) {
  const left = createHash("sha256").update(String(a)).digest();
  const right = createHash("sha256").update(String(b)).digest();
  return timingSafeEqual(left, right) && String(a).length === String(b).length;
}
