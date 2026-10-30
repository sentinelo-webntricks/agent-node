import { readFileSync } from "node:fs";

/**
 * Lit un fichier `.env` sans dépendance : `CLÉ=valeur`, guillemets simples ou doubles,
 * commentaires `#`, préfixe `export` toléré. Un fichier absent rend un objet vide — l'agent
 * lit plusieurs sources et aucune n'est obligatoire à elle seule.
 *
 * @param {string} path
 * @returns {Record<string, string>}
 */
export function readEnvFile(path) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return {};
  }
  return parseEnv(text);
}

/** @param {string} text */
export function parseEnv(text) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$/.exec(line);
    if (!m) {
      continue;
    }
    let value = m[2];
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.lastIndexOf(quote) > 0) {
      value = value.slice(1, value.lastIndexOf(quote));
      if (quote === '"') {
        value = value.replace(/\\n/g, "\n").replace(/\\"/g, '"');
      }
    } else {
      value = value.replace(/\s+#.*$/, "").trim();
    }
    out[m[1]] = value;
  }
  return out;
}

/** Une ligne `CLÉ=valeur` sûre à relire par {@link parseEnv}. */
export function formatEnvLine(name, value) {
  return `${name}="${String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}
