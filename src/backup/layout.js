import { existsSync } from "node:fs";
import { lstat, readdir } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

/**
 * Ce qui part dans une archive, et sous quel nom.
 *
 * La plateforme parle en quatre jetons — `db`, `plugins`, `themes`, `uploads` — hérités de
 * l'agent de référence. Pour un projet Node :
 *
 * | jeton     | répertoire                                   | préfixe d'archive |
 * |-----------|----------------------------------------------|-------------------|
 * | `plugins` | le code : la racine, moins ce qui suit        | `files/source/`   |
 * | `themes`  | `public/` (moins les envois s'ils y vivent)   | `files/public/`   |
 * | `uploads` | `public/uploads`, `uploads` ou `storage`      | `files/uploads/`  |
 *
 * Les trois sont disjoints : le code exclut `public/` et le dossier d'envois, sans quoi
 * chaque fichier public partirait deux fois.
 *
 * ## Ce qui ne part jamais
 *
 * Ce qui se reconstruit (`node_modules`, `.next`, `dist`, `build`…) : le sauvegarder
 * multiplie l'archive par dix pour un contenu que `npm ci && npm run build` refait. Et les
 * `.env*` : ils portent les secrets du site, et l'agent Composer les tient lui aussi hors
 * des archives — ils se retrouvent dans le gestionnaire de secrets du client, pas dans un
 * seau.
 */

export const DEFAULT_EXCLUDES = [
  "node_modules", ".git", ".svn", ".hg", ".next", ".nuxt", ".output", ".svelte-kit", ".turbo",
  ".vercel", ".cache", ".parcel-cache", ".angular", "dist", "build", "coverage", ".nyc_output", "tmp",
];

const EXCLUDED_FILES = [/^\.env(\..*)?$/, /\.log$/, /\.tmp$/, /\.temp$/, /^\.DS_Store$/];

const UPLOAD_CANDIDATES = ["public/uploads", "uploads", "storage"];

/**
 * @param {import("../settings.js").Settings} settings
 * @returns {{role: string, prefix: string, dir: string|null, exclude: string[]}[]}
 */
export function roles(settings) {
  const root = settings.projectRoot;
  const abs = (p) => (p ? (isAbsolute(p) ? p : resolve(root, p)) : null);

  const uploads = abs(settings.paths.uploads) ?? UPLOAD_CANDIDATES.map((c) => resolve(root, c)).find((p) => existsSync(p)) ?? null;
  const publicDir = abs(settings.paths.public) ?? (existsSync(resolve(root, "public")) ? resolve(root, "public") : null);
  const source = abs(settings.paths.source) ?? root;

  const notInside = (dir) => [uploads, publicDir, settings.dataDir].filter((d) => d && d !== dir && isInside(d, dir));

  return [
    { role: "plugins", prefix: "files/source/", dir: source, exclude: notInside(source) },
    { role: "themes", prefix: "files/public/", dir: publicDir, exclude: notInside(publicDir) },
    { role: "uploads", prefix: "files/uploads/", dir: uploads, exclude: [settings.dataDir].filter((d) => uploads && isInside(d, uploads)) },
  ];
}

function isInside(child, parent) {
  if (!parent) {
    return false;
  }
  const rel = relative(parent, child);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/**
 * Le plan : chaque fichier, son nom dans l'archive et sa taille au moment du parcours.
 * Figé avant d'écrire — un fichier apparu entre-temps attendra la sauvegarde suivante.
 *
 * @param {ReturnType<typeof roles>} selected
 * @param {string[]} extraExcludes chemins relatifs à la racine, ou motifs de nom (`*.mp4`)
 */
export async function planFiles(selected, extraExcludes = []) {
  const plan = [];
  const patterns = extraExcludes.map(globToRegex);

  for (const role of selected) {
    if (!role.dir || !existsSync(role.dir)) {
      continue;
    }
    const excludedDirs = new Set(role.exclude.map((d) => resolve(d)));

    const walk = async (dir) => {
      let names;
      try {
        names = await readdir(dir);
      } catch {
        return;
      }
      for (const name of names) {
        const full = join(dir, name);
        let info;
        try {
          info = await lstat(full);
        } catch {
          continue;
        }
        // Les liens symboliques ne sont pas suivis : ils peuvent sortir du projet, ou
        // boucler. Un lien vers un dossier d'envois partagé se déclare dans la config.
        if (info.isSymbolicLink()) {
          continue;
        }
        const rel = relative(role.dir, full).split(sep).join("/");
        if (patterns.some((re) => re.test(rel) || re.test(name))) {
          continue;
        }
        if (info.isDirectory()) {
          if (DEFAULT_EXCLUDES.includes(name) || excludedDirs.has(resolve(full))) {
            continue;
          }
          await walk(full);
        } else if (info.isFile()) {
          if (EXCLUDED_FILES.some((re) => re.test(name))) {
            continue;
          }
          plan.push({ source: full, entry: `${role.prefix}${rel}`, size: info.size, mtime: Math.floor(info.mtimeMs / 1000) });
        }
      }
    };
    await walk(role.dir);
  }
  return plan;
}

function globToRegex(pattern) {
  const escaped = String(pattern)
    .replace(/^\/+/, "")
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .replace(/\u0000/g, ".*");
  return new RegExp(`(^|/)${escaped}($|/)`, "i");
}

/** Ce qu'une restauration ne touche jamais, même s'il est dans l'archive. */
export const RESTORE_SKIP = [/(^|\/)node_modules(\/|$)/, /(^|\/)\.env(\.[^/]*)?$/, /(^|\/)\.git(\/|$)/, /(^|\/)\.next(\/|$)/];
