import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Quelle application tourne ici, et en quelle version.
 *
 * L'ordre compte : un projet Next.js dépend souvent aussi d'`express` (serveur
 * personnalisé), un projet Nest embarque `express` sous le capot. Le cadre le plus
 * SPÉCIFIQUE gagne, et `express` / `fastify` ne nomment l'application que faute de mieux.
 *
 * La version est celle INSTALLÉE (`node_modules/<paquet>/package.json`), à défaut celle
 * du verrou, à défaut la contrainte déclarée — et `""` quand rien ne le dit : le backend
 * sait afficher « inconnu », il ne sait pas désapprendre un nombre plausible.
 */

const FRAMEWORKS = [
  { slug: "nextjs", name: "Next.js", pkg: "next" },
  { slug: "nuxt", name: "Nuxt", pkg: "nuxt" },
  { slug: "remix", name: "Remix", pkg: "@remix-run/node" },
  { slug: "sveltekit", name: "SvelteKit", pkg: "@sveltejs/kit" },
  { slug: "astro", name: "Astro", pkg: "astro" },
  { slug: "nestjs", name: "NestJS", pkg: "@nestjs/core" },
  { slug: "adonisjs", name: "AdonisJS", pkg: "@adonisjs/core" },
  { slug: "strapi", name: "Strapi", pkg: "@strapi/strapi" },
  { slug: "fastify", name: "Fastify", pkg: "fastify" },
  { slug: "express", name: "Express", pkg: "express" },
  { slug: "koa", name: "Koa", pkg: "koa" },
];

function readJsonFile(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

/** @param {string} projectRoot */
export function detectApplication(projectRoot) {
  const manifest = readJsonFile(join(projectRoot, "package.json")) ?? {};
  const declared = { ...(manifest.devDependencies ?? {}), ...(manifest.dependencies ?? {}) };

  const framework = FRAMEWORKS.find((f) => f.pkg in declared) ?? null;
  if (framework === null) {
    return {
      slug: "node",
      name: manifest.name ? `Node.js (${manifest.name})` : "Node.js",
      package: null,
      version: "",
      projectName: manifest.name ?? null,
    };
  }

  return {
    slug: framework.slug,
    name: framework.name,
    package: framework.pkg,
    version: installedVersion(projectRoot, framework.pkg) ?? cleanRange(declared[framework.pkg]),
    projectName: manifest.name ?? null,
  };
}

/** @param {string} projectRoot @param {string} pkg */
export function installedVersion(projectRoot, pkg) {
  const installed = readJsonFile(join(projectRoot, "node_modules", pkg, "package.json"));
  if (installed?.version) {
    return String(installed.version);
  }
  const lock = readJsonFile(join(projectRoot, "package-lock.json"));
  const fromLock = lock?.packages?.[`node_modules/${pkg}`]?.version ?? lock?.dependencies?.[pkg]?.version;
  return fromLock ? String(fromLock) : null;
}

/** `^14.2.3` → `14.2.3` ; une contrainte qui ne nomme pas une version → `""`. */
function cleanRange(range) {
  const m = /(\d+\.\d+\.\d+(?:[-+][\w.]+)?)/.exec(String(range ?? ""));
  return m ? m[1] : "";
}

/** La version de Node qui exécute l'AGENT — celle de l'application est la même en pratique. */
export function nodeVersion() {
  return process.versions.node;
}
