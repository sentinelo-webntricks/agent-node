import { iso } from "../support/timestamps.js";
import { AGENT_VERSION } from "../version.js";

/**
 * L'enveloppe de réponse commune à tous les agents Sentinelo — jumelle de
 * `AgentCore\Http\Envelope`.
 *
 *     { "success": true,  "data": {...},                             "meta": {...} }
 *     { "success": false, "error": {"code","message","http_status"}, "meta": {...} }
 *
 * **`error` est un OBJET**, jamais une chaîne : le backend le lit à un seul endroit
 * (`App\Service\Agent\AgentEnvelope`), et une chaîne arriverait à l'opérateur en JSON brut.
 *
 * `meta.php_version` vaut `null` : il n'y a pas de PHP ici, et un nombre inventé serait un
 * mensonge dans un champ que la plateforme stocke. Le moteur réel voyage à côté, sous
 * `runtime` / `node_version`.
 */
export class Envelope {
  /** @param {{slug: string, version: string}} application @param {number} [startedAt] */
  constructor(application, startedAt = Date.now()) {
    this.application = application;
    this.startedAt = startedAt;
  }

  success(data, status = 200) {
    return { status, body: { success: true, data, meta: this.meta() } };
  }

  error(code, message, status) {
    return {
      status,
      body: { success: false, error: { code, message, http_status: status }, meta: this.meta() },
    };
  }

  meta() {
    return {
      plugin_version: AGENT_VERSION,
      application: this.application.slug,
      application_version: this.application.version,
      php_version: null,
      runtime: "node",
      node_version: process.versions.node,
      timestamp: iso(),
      execution_time_ms: Math.round(Date.now() - this.startedAt),
    };
  }
}

/** L'agent ne sait même pas se décrire : réponse construite à la main, `error` objet quand même. */
export function bootstrapFailure(error) {
  return {
    status: 503,
    body: {
      success: false,
      error: {
        code: "NOT_INITIALISED",
        message: `L'agent n'a pas pu s'initialiser : ${error?.message ?? error}`,
        http_status: 503,
      },
      meta: { plugin_version: AGENT_VERSION, php_version: null, runtime: "node", node_version: process.versions.node, timestamp: iso() },
    },
  };
}
