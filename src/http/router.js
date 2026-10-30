import { statfs } from "node:fs/promises";

import { bootstrapFailure } from "./envelope.js";
import { backupPayload, restorePayload } from "../backup/payloads.js";
import { BackupAlreadyRunning, BaseBackupRequired } from "../backup/errors.js";
import { DEFAULT_LINES, MAX_LINES } from "../logging.js";
import { wire, durationSeconds } from "../support/timestamps.js";
import { AGENT_VERSION } from "../version.js";

/**
 * La table des routes — jumelle de `AgentCore\Http\Router` : mêmes noms, mêmes refus,
 * mêmes formes de réponse. Le backend construit ses appels depuis `AgentRoute`, et n'a
 * aucune raison de savoir qu'il parle à un agent écrit dans un autre langage.
 *
 * ## Les longues opérations
 *
 * Sauvegarde, restauration et scan démarrent puis rendent la main au plus tard après
 * {@link SYNC_WAIT_MS} : s'ils ont fini, la réponse porte le résultat ; sinon elle porte
 * la ligne « en cours », et la plateforme — qui traite déjà une expiration du
 * déclenchement comme « en cours » — sonde les routes de statut. Le travail, lui, continue
 * dans le démon : il ne dépend pas de la connexion qui l'a demandé.
 */

const SYNC_WAIT_MS = 20_000;

const SECURITY_ACTIONS = ["hardening", "hardening/apply", "integrity", "integrity/restore", "malware/scan", "waf", "login-block", "sso/token"];

/** Corps d'abord, puis requête : un corps JSON explicite l'emporte sur une valeur restée dans l'URL. */
function param(request, name, fallback = null) {
  if (request.body && request.body[name] !== undefined && request.body[name] !== null) {
    return request.body[name];
  }
  const fromQuery = request.query.get(name);
  return fromQuery === null ? fallback : fromQuery;
}

/** Jamais `Number(x) || 0` : une chaîne qui vaudrait 0 désignerait silencieusement un autre travail. */
function intParam(request, name) {
  const value = param(request, name);
  return value !== null && value !== "" && /^\s*\d+\s*$/.test(String(value)) ? Number(value) : null;
}

function boolParam(request, name, fallback) {
  const value = param(request, name, fallback);
  if (typeof value === "boolean") {
    return value;
  }
  return !["0", "false", "no", "off", ""].includes(String(value).toLowerCase());
}

function optionalString(request, name) {
  const value = param(request, name);
  if (typeof value !== "string") {
    return null;
  }
  return value.trim() === "" ? null : value.trim();
}

async function within(promise, ms) {
  let timer;
  const timeout = new Promise((resolvePromise) => {
    timer = setTimeout(() => resolvePromise(undefined), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

export class Router {
  /** @param {import("../agent.js").Agent} agent */
  constructor(agent) {
    this.agent = agent;
  }

  async handle(request) {
    let envelope;
    try {
      envelope = this.agent.envelope();
    } catch (e) {
      return bootstrapFailure(e);
    }

    const route = request.route;
    try {
      const denial = this.agent.authenticator.authorise(request);
      if (denial !== null) {
        return envelope.error(denial.code, denial.message, denial.status);
      }

      switch (route) {
        case "health": return this.health(envelope);
        case "site-info": return await this.siteInfo(envelope);
        case "plugins": return this.packages(envelope);
        case "themes": return this.themes(envelope);
        case "backup/run": return await this.backupRun(envelope, request);
        case "backup/status": return this.backupStatus(envelope, request);
        case "backup/resume": return this.backupResume(envelope);
        case "backup/abandon": return this.backupAbandon(envelope, request);
        case "backup/restore": return await this.restore(envelope, request);
        case "backup/restore-status": return this.restoreStatus(envelope, request);
        case "cloud-config": return this.cloudConfig(envelope, request);
        case "security/scan/run": return await this.scanRun(envelope, request);
        case "security/report": return this.securityReport(envelope, request);
        case "updates/apply":
        case "auto-updates": return this.updates(envelope);
        case "actions/apply": return this.actions(envelope, request);
        case "audit/run":
        case "audit/report": return envelope.error("NOT_SUPPORTED", "L'audit SEO n'est pas fourni par cet agent.", 501);
        case "logs": return this.logs(envelope, request);
        case "rollbacks": return this.rollbacks(envelope);
        case "rollbacks/restore": return envelope.error("NOT_SUPPORTED", this.updatesRefusal("package"), 501);
        default:
          if (SECURITY_ACTIONS.includes(route)) {
            return envelope.error("NOT_SUPPORTED", `Action de sécurité non prise en charge par l'agent de cette plateforme : ${route}`, 501);
          }
          return envelope.error("NOT_FOUND", `Route inconnue : ${route}`, 404);
      }
    } catch (e) {
      if (e instanceof BaseBackupRequired) {
        return envelope.error("VALIDATION_ERROR", e.message, 400);
      }
      this.agent.logger.error("api", `${route} : ${e?.message ?? e}`);
      return envelope.error("INTERNAL_ERROR", String(e?.message ?? e), 500);
    }
  }

  // ─── Surveillance ──────────────────────────────────────────────────────────

  health(envelope) {
    const app = this.agent.application();
    const latestScan = this.agent.scans.findLatestTerminal();
    const latestBackup = this.agent.backups.findLatest(["safety"]);
    return envelope.success({
      status: "ok",
      application: app.slug,
      application_version: app.version,
      php_version: null,
      runtime: "node",
      node_version: process.versions.node,
      agent_version: AGENT_VERSION,
      maintenance_mode: this.agent.maintenance.isEnabled(),
      last_backup_at: wire(latestBackup?.completed_at ?? null),
      last_scan_at: wire(latestScan?.completed_at ?? null),
      last_scan_score: latestScan?.score === null || latestScan?.score === undefined ? null : Number(latestScan.score),
      supports_package_updates: false,
      supports_self_update: false,
      resumable: { archive: null, encrypt: null, upload: this.agent.backupRunner.uploadState() },
    });
  }

  async siteInfo(envelope) {
    const app = this.agent.application();
    const root = this.agent.settings.projectRoot;
    let free = null;
    let total = null;
    try {
      const s = await statfs(root);
      free = Number(s.bavail) * Number(s.bsize);
      total = Number(s.blocks) * Number(s.bsize);
    } catch {
      // « inconnu » n'est pas « zéro ».
    }
    const inventory = this.agent.inventory();
    return envelope.success({
      application: app.slug,
      application_name: app.name,
      application_version: app.version,
      php_version: null,
      runtime: "node",
      node_version: process.versions.node,
      agent_version: AGENT_VERSION,
      site_url: String(this.agent.config.get("site_url") || this.agent.settings.siteUrl || ""),
      project_root: root,
      database_name: this.agent.database()?.databaseName() ?? null,
      database_engine: this.agent.database()?.engine ?? null,
      server_software: `Node.js ${process.versions.node}`,
      packages_count: inventory.components.length,
      supports_package_updates: false,
      disk_free_bytes: free,
      disk_total_bytes: total,
    });
  }

  packages(envelope) {
    const { components, source } = this.agent.inventory();
    return envelope.success({
      total: components.length,
      updates_available: 0,
      plugins: components,
      supported: true,
      supported_reason: "La plateforme gère ce type de composant : l'agent le déclare.",
      source,
      update_detection: "unavailable",
      update_detection_reason: components[0]?.update_detection_reason ?? "Aucun fichier de verrouillage lisible (package-lock.json, pnpm-lock.yaml, yarn.lock).",
    });
  }

  themes(envelope) {
    return envelope.success({
      active: null,
      installed: [],
      total: 0,
      updates_available: 0,
      supported: false,
      supported_reason: "La plateforme n'a pas cette notion. La liste est vide parce qu'il n'y a rien à lister, pas parce que rien n'est installé.",
      source: null,
      update_detection: "unavailable",
      update_detection_reason: "Aucun thème n'est géré par un projet Node.js.",
    });
  }

  rollbacks(envelope) {
    return envelope.success({
      supported: false,
      snapshots: [],
      total: 0,
      keep_per_component: 3,
      max_age_days: 30,
      scope: "Cet agent n'applique aucune mise à jour, donc ne garde aucun instantané de composant.",
    });
  }

  // ─── Sauvegarde ────────────────────────────────────────────────────────────

  async backupRun(envelope, request) {
    const options = {
      type: String(param(request, "type", "manual")),
      includes: toList(param(request, "includes", ["db", "plugins", "themes", "uploads"])),
      exclude_paths: toList(param(request, "exclude_paths", [])),
      mode: String(param(request, "mode", "full")),
      cloud_upload: boolParam(request, "cloud_upload", true),
      comment: String(param(request, "comment", "")),
    };

    let started;
    try {
      started = this.agent.backupRunner.start(options);
    } catch (e) {
      if (e instanceof BackupAlreadyRunning) {
        return envelope.error("CONFLICT", e.message, 409);
      }
      if (e?.code === "VALIDATION_ERROR") {
        return envelope.error("VALIDATION_ERROR", e.message, 400);
      }
      throw e;
    }

    await within(started.done, SYNC_WAIT_MS);
    const row = this.agent.backups.find(started.id);
    return envelope.success(row === null ? { backup_id: started.id, status: "in_progress" } : backupPayload(row));
  }

  backupStatus(envelope, request) {
    const raw = param(request, "backup_id");
    let backup;
    if (raw !== null && raw !== "") {
      const id = intParam(request, "backup_id");
      if (id === null || id <= 0) {
        return envelope.error("VALIDATION_ERROR", "backup_id invalide : identifiant numérique interne au site attendu (pas un identifiant backend).", 400);
      }
      backup = this.agent.backups.find(id);
    } else {
      // Sans identifiant : le déclenchement a expiré avant d'en rendre un. Les sauvegardes
      // de sécurité sont écartées — prises en pleine restauration, elles seraient
      // adoptées comme celle de l'appelant.
      backup = this.agent.backups.findLatest(["safety"]);
    }
    if (backup === null) {
      return envelope.error("NOT_FOUND", "Backup introuvable.", 404);
    }
    return envelope.success({ ...backupPayload(backup), history: { ...this.agent.backups.statistics(), next_scheduled: null } });
  }

  backupResume(envelope) {
    // Le démon ne s'arrête pas entre deux étapes : il n'y a rien à « pousser ». On le dit,
    // dans la forme que la plateforme sait lire.
    const id = this.agent.backups.findInProgressId();
    if (id === null) {
      return envelope.success({ resumed: false, reason: "Aucune sauvegarde en cours." });
    }
    const row = this.agent.backups.find(id);
    return envelope.success({ resumed: true, ...backupPayload(row) });
  }

  backupAbandon(envelope, request) {
    const id = intParam(request, "backup_id");
    if (id === null || id <= 0) {
      return envelope.error("VALIDATION_ERROR", "backup_id invalide : identifiant numérique interne au site attendu.", 400);
    }
    const reason = String(param(request, "reason", "") ?? "").trim() || "Abandonnée par la plateforme.";
    return envelope.success(this.agent.backupRunner.abandon(id, reason.slice(0, 250)));
  }

  async restore(envelope, request) {
    const cloudPath = String(param(request, "backup_cloud_path", "")).trim();
    const scope = String(param(request, "scope", "all"));
    const safetyBackup = boolParam(request, "safety_backup", true);
    const checksum = String(param(request, "checksum", "") ?? "").trim().toLowerCase();
    const baseCloudPath = String(param(request, "base_cloud_path", "") ?? "").trim();
    const baseChecksum = String(param(request, "base_checksum", "") ?? "").trim().toLowerCase();

    if (cloudPath === "") {
      return envelope.error("VALIDATION_ERROR", "backup_cloud_path requis.", 400);
    }
    if (checksum !== "" && !/^[a-f0-9]{64}$/.test(checksum)) {
      return envelope.error("VALIDATION_ERROR", "checksum invalide (SHA-256 hexadécimal attendu).", 400);
    }
    if (baseChecksum !== "" && !/^[a-f0-9]{64}$/.test(baseChecksum)) {
      return envelope.error("VALIDATION_ERROR", "base_checksum invalide (SHA-256 hexadécimal attendu).", 400);
    }
    // Confiné à l'espace de CE site : sans cela, un appelant authentifié restaurerait
    // n'importe quel objet du seau, y compris la sauvegarde d'un autre client.
    const siteUuid = String(this.agent.config.get("site_uuid") || "");
    const prefix = `backups/${siteUuid}/`;
    if (siteUuid === "" || !cloudPath.startsWith(prefix) || cloudPath.includes("..")) {
      return envelope.error("VALIDATION_ERROR", "backup_cloud_path hors de l'espace de sauvegarde de ce site.", 400);
    }
    if (baseCloudPath !== "" && (!baseCloudPath.startsWith(prefix) || baseCloudPath.includes(".."))) {
      return envelope.error("VALIDATION_ERROR", "base_cloud_path hors de l'espace de sauvegarde de ce site.", 400);
    }

    const inProgress = this.agent.restores.findInProgress();
    if (inProgress !== null) {
      return envelope.error("CONFLICT", `Une restauration est déjà en cours (ID: ${inProgress.id})`, 409);
    }

    const started = this.agent.restoreRunner.start({
      cloudPath,
      scope,
      safetyBackup,
      checksum: checksum || null,
      baseCloudPath: baseCloudPath || null,
      baseChecksum: baseChecksum || null,
    });
    await within(started.done, SYNC_WAIT_MS);
    const row = this.agent.restores.find(started.id);
    return envelope.success(row === null ? { restore_id: started.id } : restorePayload(row));
  }

  restoreStatus(envelope, request) {
    const id = intParam(request, "restore_id");
    const restore = id !== null ? this.agent.restores.find(id) : this.agent.restores.findLatest();
    if (restore === null) {
      return envelope.error("NOT_FOUND", "Aucune restauration trouvée.", 404);
    }
    return envelope.success(restorePayload(restore));
  }

  cloudConfig(envelope, request) {
    const provider = String(param(request, "provider", "") ?? "").trim() || "backblaze_b2";
    const nested = param(request, "credentials");
    const isNested = nested && typeof nested === "object" && !Array.isArray(nested) && Object.keys(nested).length > 0;

    const read = (name, fallback = "") => String(param(request, name, fallback) ?? "").trim();
    const credentials = isNested
      ? { ...nested }
      : {
          provider,
          key_id: read("key_id"),
          app_key: read("app_key"),
          bucket_name: read("bucket_name"),
          bucket_id: read("bucket_id"),
          region: read("region", "us-west-004") || "us-west-004",
          endpoint: read("endpoint"),
        };
    if (!credentials.provider || String(credentials.provider).trim() === "") {
      credentials.provider = provider;
    }

    if (!isNested) {
      const missing = ["key_id", "app_key", "bucket_name"].filter((k) => String(credentials[k] ?? "").trim() === "");
      if (missing.length > 0) {
        return envelope.error(
          "VALIDATION_ERROR",
          `Identifiants cloud inexploitables : ${missing.join(", ")} vide(s) ou absent(s). ` +
            "Attendu soit un objet « credentials », soit les clés plates key_id / app_key / bucket_name (plus bucket_id, region, endpoint).",
          400,
        );
      }
    }

    this.agent.config.set("cloud_provider", provider);
    this.agent.config.set("cloud_credentials", credentials);

    return envelope.success({
      configured: true,
      provider,
      bucket_name: String(credentials.bucket_name ?? credentials.bucket ?? ""),
      region: String(credentials.region ?? ""),
    });
  }

  // ─── Sécurité ──────────────────────────────────────────────────────────────

  async scanRun(envelope, request) {
    const type = String(param(request, "scan_type", param(request, "type", "full")));
    const started = this.agent.scanRunner.start(type === "quick" ? "quick" : "full");
    const result = await within(started.done, SYNC_WAIT_MS * 3);
    return envelope.success(result ?? { scan_id: started.id, status: "running" });
  }

  securityReport(envelope, request) {
    const id = intParam(request, "scan_id");
    const scan = id !== null ? this.agent.scans.find(id) : this.agent.scans.findLatestTerminal();
    if (scan === null) {
      return envelope.error("NOT_FOUND", "Aucun scan trouvé.", 404);
    }
    return envelope.success({
      scan_id: scan.id,
      scan_type: scan.scan_type,
      status: scan.status,
      score: scan.score === null || scan.score === undefined ? null : Number(scan.score),
      started_at: wire(scan.started_at),
      completed_at: wire(scan.completed_at),
      duration_seconds: durationSeconds(scan.started_at, scan.completed_at),
      error_message: scan.error_message ?? null,
      checks_passed: scan.checks_passed ?? 0,
      checks_warned: scan.checks_warned ?? 0,
      checks_failed: scan.checks_failed ?? 0,
      checks_skipped: scan.checks_skipped ?? 0,
      critical_issues: scan.critical_issues ?? 0,
      high_issues: scan.high_issues ?? 0,
      medium_issues: scan.medium_issues ?? 0,
      low_issues: scan.low_issues ?? 0,
      details: scan.details ?? [],
      vulnerabilities: scan.vulnerabilities ?? [],
      profile: this.agent.scanRunner.profileIds(),
    });
  }

  // ─── Refus explicites et actions ──────────────────────────────────────────

  updatesRefusal(type) {
    return (
      `Les mises à jour de type « ${type} » ne sont pas prises en charge sur ${this.agent.application().name} : ` +
      "aucune procédure de mise à jour en place sûre n'existe pour cette plateforme."
    );
  }

  /**
   * 501 sur tout lot : `npm update` + reconstruction + redémarrage n'est pas atomique, et
   * écrire dans `node_modules` ferait diverger le code exécuté de l'artefact du pipeline.
   */
  updates(envelope) {
    return envelope.error("NOT_SUPPORTED", this.updatesRefusal("package"), 501);
  }

  actions(envelope, request) {
    const action = String(param(request, "action", "") ?? "");
    switch (action) {
      case "flush_cache":
        return envelope.success({
          flushed: true,
          scope: "agent",
          entries: this.agent.purgeCache(),
          note: "Cache interne de l'agent uniquement — le cache applicatif relève du pipeline de déploiement du client.",
        });
      case "maintenance_on":
        this.agent.maintenance.enable();
        return envelope.success({ maintenance_mode: this.agent.maintenance.isEnabled() });
      case "maintenance_off":
        this.agent.maintenance.disable();
        return envelope.success({ maintenance_mode: this.agent.maintenance.isEnabled() });
      default:
        return envelope.error("VALIDATION_ERROR", `Action inconnue ou non prise en charge sur cette plateforme : ${action || "(vide)"}`, 400);
    }
  }

  logs(envelope, request) {
    const reader = this.agent.logReader;
    const result = reader.tail({
      date: optionalString(request, "date"),
      lines: Number(param(request, "lines") || DEFAULT_LINES),
      minLevel: optionalString(request, "level"),
      channel: optionalString(request, "channel"),
    });
    return envelope.success({ ...result, max_lines: MAX_LINES, timezone: reader.timezone() });
  }
}

function toList(value) {
  if (Array.isArray(value)) {
    return value.map(String);
  }
  if (typeof value === "string" && value !== "") {
    return value.split(",").map((s) => s.trim()).filter(Boolean);
  }
  return [];
}
