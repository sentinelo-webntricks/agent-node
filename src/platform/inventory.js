import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * L'inventaire des paquets installés — la source de la corrélation CVE côté plateforme.
 *
 * ## Le verrou, pas `node_modules`
 *
 * Comme l'agent Composer lit `composer.lock`, on lit le fichier de verrouillage : c'est ce
 * que le pipeline du client installe, transitifs compris, et c'est là que vivent la
 * plupart des vulnérabilités. Trois formats : `package-lock.json` (v1 à v3),
 * `pnpm-lock.yaml`, `yarn.lock` (v1 et berry). Le premier trouvé dans cet ordre fait foi —
 * deux verrous dans un même projet sont déjà une anomalie, et les fusionner décrirait un
 * arbre que personne n'installe.
 *
 * ## Ce que `latest_version` vaut
 *
 * `null`, toujours : INCONNU, jamais « à jour ». La version installable dépend des
 * contraintes du projet, pas de la dernière publiée — même doctrine que l'agent Composer.
 */

export const UPDATE_DETECTION_REASON =
  "La version cible dépend des contraintes du projet, pas de la dernière version publiée : " +
  "l'agent ne peut pas la déterminer et ne la devine pas.";

/** @param {string} projectRoot */
export function readLockedPackages(projectRoot) {
  const npm = readText(join(projectRoot, "package-lock.json"));
  if (npm !== null) {
    return { source: "package-lock.json", packages: fromPackageLock(npm) };
  }
  const pnpm = readText(join(projectRoot, "pnpm-lock.yaml"));
  if (pnpm !== null) {
    return { source: "pnpm-lock.yaml", packages: fromPnpmLock(pnpm) };
  }
  const yarn = readText(join(projectRoot, "yarn.lock"));
  if (yarn !== null) {
    return { source: "yarn.lock", packages: fromYarnLock(yarn) };
  }
  return { source: null, packages: [] };
}

function readText(path) {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/** Dédoublonne par `nom@version` et trie, pour qu'un même verrou rende une même liste. */
function normalise(entries) {
  const seen = new Map();
  for (const e of entries) {
    if (e.name && e.version) {
      seen.set(`${e.name}@${e.version}`, { name: e.name, version: e.version, dev: Boolean(e.dev) });
    }
  }
  return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

/** @param {string} text */
export function fromPackageLock(text) {
  let lock;
  try {
    lock = JSON.parse(text);
  } catch {
    return [];
  }
  const out = [];
  if (lock.packages && typeof lock.packages === "object") {
    for (const [path, meta] of Object.entries(lock.packages)) {
      if (path === "" || meta?.link) {
        continue;
      }
      const name = meta.name ?? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      out.push({ name, version: meta.version, dev: meta.dev });
    }
  } else if (lock.dependencies) {
    const walk = (deps) => {
      for (const [name, meta] of Object.entries(deps ?? {})) {
        out.push({ name, version: meta.version, dev: meta.dev });
        walk(meta.dependencies);
      }
    };
    walk(lock.dependencies);
  }
  return normalise(out);
}

/**
 * pnpm : les clés de `packages:` portent nom et version — `/next@14.2.3`, `next@14.2.3`,
 * `/@scope/pkg/1.2.3` (anciens formats), avec un suffixe de pairs `(react@18…)` à ignorer.
 *
 * @param {string} text
 */
export function fromPnpmLock(text) {
  const out = [];
  let inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inPackages = /^(packages|snapshots):\s*$/.test(line);
      continue;
    }
    if (!inPackages) {
      continue;
    }
    const m = /^ {2}['"]?\/?((?:@[^/@\s]+\/)?[^/@\s('"]+)[@/](\d[^('":\s]*)/.exec(line);
    if (m) {
      out.push({ name: m[1], version: m[2] });
    }
  }
  return normalise(out);
}

/**
 * yarn : un bloc par ensemble de contraintes, `"next@^14", next@14.2.x:` puis
 * `  version "14.2.3"` (v1) ou `  version: 14.2.3` (berry).
 *
 * @param {string} text
 */
export function fromYarnLock(text) {
  const out = [];
  let names = [];
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line) && line.trim().endsWith(":") && !line.startsWith("#") && !line.startsWith("__metadata")) {
      names = line
        .slice(0, -1)
        .split(",")
        .map((s) => s.trim().replace(/^"|"$/g, ""))
        .map((spec) => spec.slice(0, spec.indexOf("@", 1)))
        .filter(Boolean);
      continue;
    }
    const v = /^ {2}version:? "?([^"\s]+)"?/.exec(line);
    if (v && names.length > 0) {
      out.push({ name: names[0], version: v[1] });
      names = [];
    }
  }
  return normalise(out);
}

/**
 * Les composants au format du contrat (`InstalledComponent::toArray`).
 *
 * @param {{name: string, version: string}[]} packages
 * @param {string|null} source
 */
export function toComponents(packages, source) {
  return packages.map((p) => ({
    type: "package",
    slug: p.name,
    name: p.name,
    version: p.version,
    latest_version: null,
    update_available: false,
    active: false,
    auto_update: false,
    source,
    update_detection_reason: UPDATE_DETECTION_REASON,
  }));
}
