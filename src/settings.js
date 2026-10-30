import { readFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

import { readEnvFile } from "./support/dotenv.js";

/**
 * Où vit quoi, pour UN projet supervisé.
 *
 * ## Les sources, de la plus forte à la plus faible
 *
 * 1. l'environnement du processus (`systemd`, Docker, PM2) ;
 * 2. `<data-dir>/agent.env` — écrit par `sentinelo-agent init`, il porte le secret de
 *    chiffrement, que l'agent ne range JAMAIS dans le projet (souvent un dépôt git,
 *    reconstruit à chaque déploiement) ;
 * 3. les `.env` du projet — `.env.production.local`, `.env.local`, `.env.production`,
 *    `.env` — pour `DATABASE_URL` / `MONGODB_URI`, que l'application lit déjà ;
 * 4. `sentinelo.config.json` à la racine du projet, pour ce qui n'est pas un secret.
 *
 * ## Le répertoire de données
 *
 * L'état de l'agent (clé d'API scellée, historique des sauvegardes, journaux, archives
 * de travail) vit dans un répertoire À LUI, pas dans la base du client. Trois raisons :
 * la base peut être MongoDB, qui n'a pas de tables ; rien n'est donc à exclure du dump ;
 * et une restauration ne rembobine jamais la clé qui la pilote — le défaut que l'agent PHP
 * a dû corriger avec `AgentOwnedTables` et `SettingsPreservation`.
 */

export const DEFAULT_SAAS_URL = "https://backend.sentinelo.fr";
export const DEFAULT_PORT = 8787;
export const DEFAULT_HOST = "127.0.0.1";

const PROJECT_ENV_FILES = [".env", ".env.production", ".env.local", ".env.production.local"];

/**
 * @param {{projectRoot?: string, configPath?: string, env?: Record<string, string|undefined>}} [options]
 */
export function loadSettings(options = {}) {
  const processEnv = options.env ?? process.env;
  const projectRoot = resolve(options.projectRoot ?? processEnv.SENTINELO_PROJECT_ROOT ?? process.cwd());
  const configPath = options.configPath ?? processEnv.SENTINELO_CONFIG ?? join(projectRoot, "sentinelo.config.json");
  const file = readConfigFile(configPath);

  const dataDir = absolute(projectRoot, processEnv.SENTINELO_DATA_DIR ?? file.dataDir ?? ".sentinelo");

  // Les fichiers du projet d'abord, chacun écrasant le précédent (l'ordre de Next.js),
  // puis agent.env, puis le processus.
  /** @type {Record<string, string|undefined>} */
  const env = {};
  for (const name of PROJECT_ENV_FILES) {
    Object.assign(env, readEnvFile(join(projectRoot, name)));
  }
  Object.assign(env, readEnvFile(join(dataDir, "agent.env")));
  for (const [k, v] of Object.entries(processEnv)) {
    if (v !== undefined) {
      env[k] = v;
    }
  }

  const paths = file.paths ?? {};

  return {
    projectRoot,
    configPath,
    dataDir,
    env,
    host: env.SENTINELO_HOST ?? file.host ?? DEFAULT_HOST,
    port: Number(env.SENTINELO_PORT ?? file.port ?? DEFAULT_PORT),
    siteUrl: env.SENTINELO_SITE_URL ?? file.siteUrl ?? "",
    saasUrl: env.SENTINELO_SAAS_URL ?? file.saasUrl ?? null,
    databaseUrl: env.SENTINELO_DATABASE_URL ?? file.database?.url ?? env.DATABASE_URL ?? env.MONGODB_URI ?? env.MONGO_URL ?? null,
    paths: {
      source: paths.source ?? null,
      public: paths.public ?? null,
      uploads: paths.uploads ?? null,
    },
    excludePaths: Array.isArray(file.excludePaths) ? file.excludePaths : [],
    file,
  };
}

/** @typedef {ReturnType<typeof loadSettings>} Settings */

function readConfigFile(path) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return {};
  }
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (e) {
    // Un fichier illisible n'est pas un fichier absent : on le dit plutôt que de
    // démarrer sur des défauts que personne n'a choisis.
    throw new Error(`${path} n'est pas un JSON valide : ${e.message}`);
  }
}

function absolute(root, path) {
  return isAbsolute(path) ? path : resolve(root, path);
}
