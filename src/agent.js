import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { BackupRunner } from "./backup/runner.js";
import { RestoreRunner } from "./backup/restore.js";
import { databaseFromUrl } from "./backup/database.js";
import { deriveKey } from "./crypto/sntlo.js";
import { Authenticator } from "./http/authenticator.js";
import { Envelope } from "./http/envelope.js";
import { Router } from "./http/router.js";
import { Logger, LogReader } from "./logging.js";
import { detectApplication } from "./platform/detect.js";
import { readLockedPackages, toComponents } from "./platform/inventory.js";
import { ScanRunner } from "./scan/runner.js";
import { DEFAULT_SAAS_URL, loadSettings } from "./settings.js";
import { ConfigStore } from "./state/configStore.js";
import { BackupRepository, RestoreRepository, ScanRepository } from "./state/repositories.js";
import { ObjectStorage } from "./storage/s3.js";
import { Webhooks } from "./webhook.js";

/**
 * La racine de composition : un agent pour UN projet.
 *
 * Tout ce qui lit le disque du projet (application, inventaire, base) est relu à la
 * demande plutôt que figé au démarrage : un déploiement change `package.json` et le
 * verrou sous un démon qui tourne depuis des semaines, et la plateforme doit voir la
 * version déployée, pas celle du jour où l'agent a démarré.
 */
export class Agent {
  /** @param {import("./settings.js").Settings} [settings] @param {{echoLogs?: boolean}} [options] */
  constructor(settings = loadSettings(), options = {}) {
    this.settings = settings;
    mkdirSync(settings.dataDir, { recursive: true, mode: 0o700 });

    this.logger = new Logger(join(settings.dataDir, "logs"), { echo: options.echoLogs ?? false });
    this.logReader = new LogReader(join(settings.dataDir, "logs"));
    this.config = new ConfigStore(settings.dataDir, () => this.cryptoKey());
    this.backups = new BackupRepository(settings.dataDir);
    this.restores = new RestoreRepository(settings.dataDir);
    this.scans = new ScanRepository(settings.dataDir);
    this.authenticator = new Authenticator(this.config, this.logger);
    this.webhooks = new Webhooks(this);
    this.backupRunner = new BackupRunner(this);
    this.restoreRunner = new RestoreRunner(this);
    this.scanRunner = new ScanRunner(this);
    this.router = new Router(this);
    this.maintenance = new MaintenanceFlag(join(settings.dataDir, "maintenance.flag"));
    this.key = null;
  }

  cryptoKey() {
    if (this.key === null) {
      this.key = deriveKey(this.settings.env);
    }
    return this.key;
  }

  application() {
    return detectApplication(this.settings.projectRoot);
  }

  envelope() {
    return new Envelope(this.application());
  }

  inventory() {
    const { source, packages } = readLockedPackages(this.settings.projectRoot);
    return { source, components: toComponents(packages, source) };
  }

  /** @returns {import("./backup/database.js").Database|null} */
  database() {
    return databaseFromUrl(this.settings.databaseUrl, this.settings.projectRoot);
  }

  /** L'adresse de la plateforme : celle enregistrée à l'enrôlement fait foi. */
  saasUrl() {
    return String(this.config.get("saas_url") || this.settings.saasUrl || DEFAULT_SAAS_URL);
  }

  /** Lève `StorageRefusal("Cloud credentials not configured")` sans identifiants. */
  storage() {
    const credentials = this.config.get("cloud_credentials") ?? {};
    return new ObjectStorage(String(this.config.get("cloud_provider") || credentials.provider || "backblaze_b2"), credentials);
  }

  /** `flush_cache` : le cache de l'agent seulement — ici, la file de webhooks morts. */
  purgeCache() {
    return this.webhooks.queue.removeWhere((r) => r.status !== "pending");
  }

  /** @param {{route: string, method: string, ip: string, headers: Record<string,string>, query: URLSearchParams, body: any}} request */
  handle(request) {
    return this.router.handle(request);
  }
}

/**
 * Le mode maintenance : un drapeau sur disque. L'agent ne sert pas l'application — c'est
 * le proxy inverse qui rend 503 tant que le fichier existe (voir le README) : le seul
 * composant placé devant TOUTES les requêtes du site.
 */
class MaintenanceFlag {
  constructor(path) {
    this.path = path;
  }

  enable() {
    writeFileSync(this.path, new Date().toISOString(), { mode: 0o644 });
  }

  disable() {
    rmSync(this.path, { force: true });
  }

  isEnabled() {
    return existsSync(this.path);
  }
}
