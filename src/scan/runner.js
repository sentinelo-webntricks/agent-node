import { existsSync } from "node:fs";
import { lstat, readdir, stat } from "node:fs/promises";
import { connect } from "node:tls";
import { join, relative, sep } from "node:path";

import { request } from "../support/http.js";
import { store } from "../support/timestamps.js";
import { roles } from "../backup/layout.js";
import {
  PROFILE, QUICK_PROFILE, WEIGHTS, aggregate, alertSeverity, calculateScore, scoreConfigFile, scoreDebugMode,
  scoreDirectoryListing, scoreFilePermissions, scoreRuntimeVersion, scoreSecurityHeaders, scoreSensitiveFiles,
  scoreSsl, scoreSuspiciousFiles, warrantsAlert,
} from "./checks.js";

/**
 * Le scan de sécurité d'un projet Node — jumeau de `ScanRunner` (agent Composer).
 *
 * Un check qui lève devient un résultat `error` au lieu d'emporter le scan : la notation
 * l'exclut du numérateur ET du dénominateur, donc une sonde injoignable coûte son check,
 * pas le scan, et ne peut pas non plus gonfler la note.
 */

const SENSITIVE_PATHS = ["/.env", "/.env.local", "/.env.production", "/.npmrc", "/.git/config", "/package.json", "/package-lock.json", "/npm-debug.log"];
const LISTING_PATHS = ["/uploads/", "/static/", "/public/", "/assets/", "/files/"];

/** Ce qui s'exécute côté serveur — rien à faire dans un dossier d'envois. */
const EXECUTABLE = /\.(php\d?|phtml|phar|cgi|pl|py|sh|exe|dll|so|jsp|aspx?|js|mjs|cjs|node)$/i;
const SWEEP_LIMIT = 50_000;

export class ScanRunner {
  /** @param {import("../agent.js").Agent} agent */
  constructor(agent) {
    this.agent = agent;
    this.current = null;
  }

  profileIds() {
    return PROFILE;
  }

  /** @returns {{id: number, done: Promise<any>}} */
  start(type) {
    // Un scan à la fois : deux scans simultanés sonderaient deux fois le même site.
    if (this.current !== null) {
      return this.current;
    }
    const id = this.agent.scans.insert({ scan_type: type, status: "running", started_at: store(), completed_at: null, score: null });
    const done = this.run(id, type).finally(() => {
      this.current = null;
    });
    this.current = { id, done };
    return this.current;
  }

  async run(id, type) {
    const { logger, scans, webhooks } = this.agent;
    const ids = type === "quick" ? QUICK_PROFILE : PROFILE;
    try {
      const results = [];
      for (const check of ids) {
        try {
          results.push(await this.collect(check));
        } catch (e) {
          logger.warning("security", `Check ${check} en erreur : ${e.message}`);
          results.push({ name: check, status: "error", score: 0, maxScore: WEIGHTS[check], severity: "info", details: { error: e.message }, recommendation: `Vérification impossible : ${e.message}`, vulnerabilities: [] });
        }
      }
      const { score, label } = calculateScore(results);
      const summary = aggregate(results);
      scans.update(id, { status: "completed", completed_at: store(), score, ...summary });

      await webhooks.send("security.scan_complete", { scan_id: id, scan_type: type, status: "completed", score, ...summary });
      if (warrantsAlert(score, summary.critical_issues)) {
        await webhooks.send("security.alert", { scan_id: id, severity: alertSeverity(summary.critical_issues), score, critical_issues: summary.critical_issues });
      }
      logger.info("security", `Scan #${id} terminé : ${score}/100`);
      return { scan_id: id, score, label };
    } catch (e) {
      scans.update(id, { status: "failed", completed_at: store(), error_message: e.message });
      logger.error("security", `Scan #${id} échoué : ${e.message}`);
      throw e;
    }
  }

  async collect(check) {
    switch (check) {
      case "runtime_version": return scoreRuntimeVersion(process.versions.node);
      case "debug_mode": return scoreDebugMode(this.debugFacts());
      case "ssl": return this.ssl();
      case "security_headers": return scoreSecurityHeaders((await this.fetch("/")).headers);
      case "sensitive_files": return scoreSensitiveFiles(await this.probe(SENSITIVE_PATHS));
      case "directory_listing": return scoreDirectoryListing(await this.probe(LISTING_PATHS));
      case "config_file": return this.configFile();
      case "file_permissions": return scoreFilePermissions(await this.permissionFindings());
      case "suspicious_files": {
        const sweep = await this.suspiciousFiles();
        return scoreSuspiciousFiles(sweep.findings, sweep.complete);
      }
      case "extension_vulnerabilities": return this.packageInventory();
      default: throw new Error(`check inconnu : ${check}`);
    }
  }

  siteUrl() {
    return String(this.agent.config.get("site_url") || this.agent.settings.siteUrl || "");
  }

  /**
   * `NODE_ENV` n'est un défaut que s'il vaut EXPLICITEMENT autre chose que `production` :
   * absent, `next start` et la plupart des cadres tournent déjà en production.
   */
  debugFacts() {
    const env = this.agent.settings.env;
    const nodeEnv = String(env.NODE_ENV ?? "").toLowerCase();
    return {
      debug: nodeEnv !== "" && nodeEnv !== "production",
      debugDisplay: false,
      debugLog: String(env.DEBUG ?? "").trim() !== "",
      names: { debug: `NODE_ENV=${env.NODE_ENV ?? ""}`, debug_display: "affichage des erreurs", debug_log: "DEBUG" },
    };
  }

  ssl() {
    const site = this.siteUrl();
    const host = site ? new URL(site).hostname : "";
    if (host === "") {
      throw new Error("URL du site non configurée");
    }
    return new Promise((resolvePromise, reject) => {
      const socket = connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 10_000 }, () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol() ?? "inconnu";
        socket.end();
        if (!cert || !cert.valid_to) {
          reject(new Error("Certificat TLS illisible"));
          return;
        }
        const days = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000);
        resolvePromise(scoreSsl(days, protocol, cert.issuer?.O ?? cert.issuer?.CN ?? "inconnu"));
      });
      socket.on("timeout", () => socket.destroy(new Error("délai dépassé")));
      socket.on("error", (e) => reject(new Error(`Connexion TLS impossible : ${e.message}`)));
    });
  }

  async fetch(path) {
    const site = this.siteUrl();
    if (site === "") {
      return { code: 0, body: "", headers: {} };
    }
    const response = await request("GET", `${site.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`, { timeout: 10, maxBodyBytes: 4096 });
    return { code: response.status, body: response.body.toString("utf8").slice(0, 4096), headers: response.headers };
  }

  /** Ne garde que les chemins auxquels le serveur a RÉPONDU : un silence ne prouve rien. */
  async probe(paths) {
    const out = [];
    for (const path of paths) {
      const r = await this.fetch(path);
      if (r.code > 0) {
        out.push({ path, url: path, code: r.code, body: r.body });
      }
    }
    return out;
  }

  async configFile() {
    const root = this.agent.settings.projectRoot;
    const candidates = [".env.production.local", ".env.local", ".env.production", ".env"];
    const name = candidates.find((c) => existsSync(join(root, c))) ?? ".env";
    const present = existsSync(join(root, name));
    const publicDir = roles(this.agent.settings).find((r) => r.role === "themes")?.dir ?? null;
    const insidePublic = publicDir !== null && existsSync(join(publicDir, ".env"));
    let worldReadable = false;
    if (present) {
      worldReadable = ((await stat(join(root, name))).mode & 0o004) !== 0;
    }
    const probe = present ? await this.fetch(`/${name}`) : { code: 0, body: "" };
    const served = probe.code === 200 && probe.body.includes("=") && !/<html|<!doctype/i.test(probe.body);
    return scoreConfigFile(name, present, served, insidePublic, worldReadable);
  }

  /** Inscriptibles par tous dans le projet, et `.env` lisibles par tous. */
  async permissionFindings() {
    const root = this.agent.settings.projectRoot;
    const findings = [];
    const check = async (path, depth) => {
      let info;
      try {
        info = await lstat(path);
      } catch {
        return;
      }
      if (info.isSymbolicLink()) {
        return;
      }
      const rel = relative(root, path).split(sep).join("/") || ".";
      // Le bit « collant » (/tmp) est voulu ; on ne signale que l'écriture libre.
      if ((info.mode & 0o002) !== 0 && (info.mode & 0o1000) === 0) {
        findings.push({ path: rel, issue: "world_writable" });
      }
      if (info.isFile() && /^\.env(\..*)?$/.test(rel.split("/").pop()) && (info.mode & 0o004) !== 0) {
        findings.push({ path: rel, issue: "world_readable_secret" });
      }
      if (info.isDirectory() && depth < 2) {
        for (const name of await readdir(path).catch(() => [])) {
          if (!["node_modules", ".git", ".next", ".nuxt"].includes(name)) {
            await check(join(path, name), depth + 1);
          }
        }
      }
    };
    await check(root, 0);
    return findings;
  }

  /** Les exécutables là où seules des données sont attendues : les dossiers d'envois. */
  async suspiciousFiles() {
    const uploads = roles(this.agent.settings).find((r) => r.role === "uploads")?.dir ?? null;
    if (uploads === null || !existsSync(uploads)) {
      return { findings: [], complete: true };
    }
    const findings = [];
    let seen = 0;
    const walk = async (dir) => {
      for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
        if (++seen > SWEEP_LIMIT) {
          return false;
        }
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          if ((await walk(full)) === false) {
            return false;
          }
        } else if (entry.isFile() && EXECUTABLE.test(entry.name)) {
          findings.push({ path: relative(this.agent.settings.projectRoot, full).split(sep).join("/") });
        }
      }
      return true;
    };
    const complete = (await walk(uploads)) !== false;
    return { findings, complete };
  }

  /** Inventaire à poids nul : la corrélation CVE est faite par la plateforme. */
  packageInventory() {
    const { components, source } = this.agent.inventory();
    return {
      name: "extension_vulnerabilities",
      status: "info",
      score: 0,
      maxScore: 0,
      severity: "info",
      details: { source, count: components.length, packages: components.map((c) => ({ slug: c.slug, version: c.version })) },
      recommendation: "Inventaire transmis — la corrélation CVE est faite côté plateforme",
      vulnerabilities: [],
    };
  }
}
