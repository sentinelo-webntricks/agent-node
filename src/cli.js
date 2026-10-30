#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";

import { Agent } from "./agent.js";
import { toolAvailable } from "./backup/database.js";
import { decryptFile, deriveKey } from "./crypto/sntlo.js";
import { enrol, heartbeat } from "./enrolment.js";
import { createAgentServer, BASE_PATH } from "./http/server.js";
import { Scheduler } from "./scheduler.js";
import { loadSettings } from "./settings.js";
import { formatEnvLine } from "./support/dotenv.js";
import { AGENT_VERSION } from "./version.js";

/**
 * `sentinelo-agent` — l'agent Sentinelo pour les applications Node.js.
 *
 *     sentinelo-agent init                 prépare le répertoire de données et le secret
 *     sentinelo-agent enroll <clé>         rattache ce site à la plateforme
 *     sentinelo-agent serve                lance le démon (à confier à systemd / PM2 / Docker)
 *     sentinelo-agent status               ce que l'agent sait de lui-même
 *     sentinelo-agent run <tâche>          heartbeat | backup | scan | webhooks | cleanup
 *     sentinelo-agent decrypt <src> <dst>  déchiffre une archive de sauvegarde
 *
 * Options communes : `--project <dossier>` (défaut : le dossier courant), `--config <fichier>`.
 */

const HELP = `sentinelo-agent ${AGENT_VERSION}

Usage :
  sentinelo-agent init                  prépare le répertoire de données et génère le secret
  sentinelo-agent enroll <clé> [--saas-url <url>]
  sentinelo-agent serve                 lance le démon (systemd, PM2, Docker)
  sentinelo-agent status
  sentinelo-agent run <heartbeat|backup|scan|webhooks|cleanup>
  sentinelo-agent decrypt <archive.tar.enc> <sortie.tar>

Options : --project <dossier>   --config <sentinelo.config.json>
`;

function parseArgs(argv) {
  const positional = [];
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const [name, inline] = arg.slice(2).split("=", 2);
      options[name] = inline ?? (argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true);
    } else {
      positional.push(arg);
    }
  }
  return { positional, options };
}

const out = (line = "") => process.stdout.write(`${line}\n`);

async function main() {
  const { positional, options } = parseArgs(process.argv.slice(2));
  const command = positional[0];
  const settingsOptions = { projectRoot: options.project, configPath: options.config };

  switch (command) {
    case "init": return init(settingsOptions);
    case "enroll": return enroll(settingsOptions, positional[1] ?? process.env.SENTINELO_API_KEY, options["saas-url"]);
    case "serve": return serve(settingsOptions);
    case "status": return status(settingsOptions);
    case "run": return runTask(settingsOptions, positional[1]);
    case "decrypt": return decrypt(settingsOptions, positional[1], positional[2]);
    case "version":
    case "--version":
      out(AGENT_VERSION);
      return 0;
    default:
      out(HELP);
      return command === undefined || command === "help" || options.help ? 0 : 2;
  }
}

async function init(settingsOptions) {
  const settings = loadSettings(settingsOptions);
  mkdirSync(settings.dataDir, { recursive: true, mode: 0o700 });
  const envFile = join(settings.dataDir, "agent.env");

  out(`Projet       : ${settings.projectRoot}`);
  out(`Données      : ${settings.dataDir}`);

  try {
    deriveKey(settings.env);
    out("Secret       : déjà défini (SENTINELO_SECRET)");
  } catch {
    const secret = randomBytes(32).toString("hex");
    appendFileSync(envFile, `${formatEnvLine("SENTINELO_SECRET", secret)}\n`, { mode: 0o600 });
    out(`Secret       : généré dans ${envFile}`);
    out("");
    out("  ⚠ GARDEZ UNE COPIE DE CE SECRET HORS DU SERVEUR. Il déchiffre les sauvegardes :");
    out("    si le serveur est perdu, il faut ce secret pour les relire.");
    out(`    SENTINELO_SECRET=${secret}`);
    out("");
  }

  const agent = new Agent(loadSettings(settingsOptions));
  const app = agent.application();
  out(`Application  : ${app.name}${app.version ? ` ${app.version}` : ""}`);
  out(`Node.js      : ${process.versions.node}`);

  let database = null;
  try {
    database = agent.database();
  } catch (e) {
    out(`Base         : ${e.message}`);
  }
  if (database) {
    out(`Base         : ${database.engine} (${database.databaseName()})`);
    for (const tool of database.tools()) {
      out(`  ${(await toolAvailable(tool)) ? "✓" : "✗"} ${tool}${(await toolAvailable(tool)) ? "" : " — introuvable : les sauvegardes de la base échoueront"}`);
    }
  } else if (database === null) {
    out("Base         : aucune (DATABASE_URL absent) — seuls les fichiers seront sauvegardés");
  }

  const inventory = agent.inventory();
  out(`Paquets      : ${inventory.components.length} (${inventory.source ?? "aucun fichier de verrouillage"})`);
  out("");
  out("Étapes suivantes :");
  out(`  1. Proxy inverse : transmettre ${BASE_PATH}* à http://${settings.host}:${settings.port} (voir le README).`);
  out("  2. Lancer le démon : sentinelo-agent serve  (sous systemd, PM2 ou Docker).");
  out("  3. Enrôler : sentinelo-agent enroll <clé affichée sur la plateforme>");
  return 0;
}

async function enroll(settingsOptions, key, saasUrl) {
  const agent = new Agent(loadSettings(settingsOptions));
  try {
    const { siteUuid, saasUrl: url } = await enrol(agent, key, saasUrl || null);
    out(`[OK] Site enrôlé : ${siteUuid}`);
    out(`Plateforme : ${url}`);
    await heartbeat(agent);
    return 0;
  } catch (e) {
    process.stderr.write(`[ERREUR] ${e.message}\n`);
    return 1;
  }
}

async function serve(settingsOptions) {
  const agent = new Agent(loadSettings(settingsOptions), { echoLogs: true });
  // La clé doit être dérivable AVANT d'accepter un appel : sans elle, aucune sauvegarde
  // ne peut être chiffrée, et mieux vaut un démon qui refuse de démarrer en le disant
  // qu'un démon qui accepte un enrôlement puis échoue à chaque sauvegarde.
  try {
    agent.cryptoKey();
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 1;
  }
  await agent.backupRunner.sweepOrphans();
  agent.backups.cancelStaleInProgress(0);

  const server = createAgentServer((request) => agent.handle(request));
  const scheduler = new Scheduler(agent);
  const { host, port } = agent.settings;

  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolvePromise);
  });
  scheduler.start();
  agent.logger.info("agent", `sentinelo-agent ${AGENT_VERSION} à l'écoute sur http://${host}:${port}${BASE_PATH} (projet ${agent.settings.projectRoot})`);

  await new Promise((resolvePromise) => {
    const stop = (signal) => {
      agent.logger.info("agent", `Arrêt (${signal})`);
      scheduler.stop();
      server.close(() => resolvePromise());
      setTimeout(resolvePromise, 5_000).unref();
    };
    process.once("SIGTERM", () => stop("SIGTERM"));
    process.once("SIGINT", () => stop("SIGINT"));
  });
  return 0;
}

async function status(settingsOptions) {
  const agent = new Agent(loadSettings(settingsOptions));
  const app = agent.application();
  const latestBackup = agent.backups.findLatest(["safety"]);
  const latestScan = agent.scans.findLatestTerminal();
  out(`Agent        : ${AGENT_VERSION}`);
  out(`Application  : ${app.name}${app.version ? ` ${app.version}` : ""} (${app.slug})`);
  out(`Plateforme   : ${agent.saasUrl()}`);
  out(`Enrôlé       : ${agent.config.get("site_uuid") ? `oui — ${agent.config.get("site_uuid")}` : "non"}`);
  out(`Stockage     : ${agent.config.get("cloud_credentials") ? "configuré" : "non configuré (poussé par la plateforme à l'enrôlement)"}`);
  out(`Maintenance  : ${agent.maintenance.isEnabled() ? "ACTIVE" : "non"}`);
  out(`Sauvegarde   : ${latestBackup ? `#${latestBackup.id} ${latestBackup.status} (${latestBackup.completed_at ?? latestBackup.started_at})` : "aucune"}`);
  out(`Scan         : ${latestScan ? `#${latestScan.id} ${latestScan.status}, ${latestScan.score ?? "—"}/100` : "aucun"}`);
  return 0;
}

async function runTask(settingsOptions, task) {
  const agent = new Agent(loadSettings(settingsOptions), { echoLogs: true });
  switch (task) {
    case "heartbeat":
      return (await heartbeat(agent)) ? 0 : 1;
    case "webhooks":
      await agent.webhooks.drain();
      return 0;
    case "cleanup":
      await new Scheduler(agent).cleanup();
      return 0;
    case "scan": {
      const result = await agent.scanRunner.start("full").done;
      out(`Scan #${result.scan_id} : ${result.score}/100 (${result.label})`);
      return 0;
    }
    case "backup": {
      const { id, done } = agent.backupRunner.start({ type: "manual", includes: ["db", "plugins", "themes", "uploads"], cloud_upload: true });
      await done;
      const row = agent.backups.find(id);
      out(`Backup #${id} : ${row.status}${row.error_message ? ` — ${row.error_message}` : ""}`);
      return row.status === "completed" ? 0 : 1;
    }
    default:
      out("Tâche inconnue. Disponibles : heartbeat, backup, scan, webhooks, cleanup");
      return 2;
  }
}

async function decrypt(settingsOptions, source, destination) {
  if (!source || !destination) {
    out("Usage : sentinelo-agent decrypt <archive.tar.enc> <sortie.tar>");
    return 2;
  }
  if (existsSync(destination)) {
    process.stderr.write(`${destination} existe déjà : refus d'écraser.\n`);
    return 1;
  }
  try {
    const key = deriveKey(loadSettings(settingsOptions).env);
    await decryptFile(key, resolve(source), resolve(destination));
    out(`Déchiffré : ${destination}`);
    return 0;
  } catch (e) {
    process.stderr.write(`Refusé : ${e.message}\n`);
    return 1;
  }
}

main().then(
  (code) => process.exit(code ?? 0),
  (e) => {
    process.stderr.write(`${e?.stack ?? e}\n`);
    process.exit(1);
  },
);
