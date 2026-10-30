/**
 * Caviarde les secrets d'une ligne de journal avant qu'elle ne quitte le site — jumeau de
 * `AgentCore\Diagnostics\Redactor`, mêmes motifs, même masque.
 */

const OPAQUE_MIN = 24;

const SENSITIVE_KEYS = [
  "api_key", "apikey", "app_key", "appkey", "secret", "password", "passwd",
  "token", "authorization", "bearer", "key_id", "access_key", "private",
];

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const KEYED = new RegExp(
  `(${SENSITIVE_KEYS.map(escape).join("|")})(["']?\\s*[:=]\\s*["']?)([^\\s"',;)\\]]+)`,
  "gi",
);

// Une suite opaque longue qui contient un chiffre : une clé recopiée sans son étiquette.
const OPAQUE = new RegExp(`\\b(?=[A-Za-z0-9_\\-]{${OPAQUE_MIN},})(?=[^\\s]*\\d)[A-Za-z0-9_\\-]+\\b`, "g");

function mask(value) {
  return value === "" ? value : `${value.slice(0, 4)}…[masqué]`;
}

/** @param {string} message */
export function scrub(message) {
  return String(message)
    .replace(KEYED, (_, key, sep, value) => key + sep + mask(value))
    .replace(OPAQUE, (m) => mask(m));
}
