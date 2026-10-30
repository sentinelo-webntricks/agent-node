/**
 * Les notations — jumelles des `Scanner/Check/*Scorer` du cœur PHP, au point près.
 *
 * Seule la COLLECTE des faits est propre à Node (voir `runner.js`) ; la notation est celle
 * de toute la flotte, parce que « 78/100 » doit vouloir dire la même chose ici que sur un
 * site WordPress — le rapport mensuel les affiche côte à côte.
 */

/** Poids du catalogue partagé (`AgentCore\Scanner\CheckCatalogue`), plus `runtime_version`. */
export const WEIGHTS = {
  suspicious_files: 15,
  file_permissions: 10,
  security_headers: 8,
  ssl: 8,
  sensitive_files: 6,
  debug_mode: 5,
  runtime_version: 5,
  config_file: 5,
  directory_listing: 2,
  extension_vulnerabilities: 0,
};

/** Le profil de cet agent : ce qu'il sait HONNÊTEMENT exécuter. Un check impossible est omis, jamais simulé. */
export const PROFILE = Object.keys(WEIGHTS);
export const QUICK_PROFILE = ["suspicious_files", "ssl", "debug_mode"];

const result = (name, status, score, maxScore, severity, details, recommendation, vulnerabilities = []) => ({
  name, status, score, maxScore, severity, details, recommendation, vulnerabilities,
});

export function scoreSecurityHeaders(headers) {
  const checks = {
    "x-frame-options": [1.5, (v) => ["deny", "sameorigin"].includes(v)],
    "x-content-type-options": [1.5, (v) => v === "nosniff"],
    "strict-transport-security": [2.0, (v) => Number(/max-age\s*=\s*"?(\d+)/.exec(v)?.[1] ?? -1) >= 15768000],
    "content-security-policy": [1.5, (v) => v !== "" && !v.includes("unsafe-inline") && !v.includes("unsafe-eval")],
    "referrer-policy": [1.0, (v) => v !== "" && !v.includes("unsafe-url") && v !== "no-referrer-when-downgrade"],
    "permissions-policy": [0.5, (v) => v !== ""],
  };
  let passed = 0;
  let total = 0;
  const issues = [];
  for (const [header, [weight, valid]] of Object.entries(checks)) {
    const raw = headers[header];
    if (raw === undefined || raw === null) {
      issues.push({ header, status: "missing" });
      continue;
    }
    const value = String(raw).trim().toLowerCase();
    if (!valid(value)) {
      issues.push({ header, status: "invalid", value });
    } else {
      passed++;
      total += weight;
    }
  }
  return result(
    "security_headers",
    passed >= 5 ? "pass" : "warn",
    Math.min(8, Math.round(total)),
    8,
    passed < 3 ? "high" : "medium",
    issues,
    issues.length === 0 ? "Headers de sécurité correctement configurés" : `${issues.length} header(s) de sécurité manquant(s) ou invalide(s)`,
  );
}

const SECRET_MARKERS = [".git", ".env", ".npmrc"];

export function scoreSensitiveFiles(responses) {
  if (responses.length === 0) {
    return result("sensitive_files", "skip", 0, 6, "info", { probed: 0 }, "Aucune sonde n'a abouti — résultat non concluant, le site n'a pas répondu");
  }
  const exposed = responses
    .filter((r) => {
      if (r.code !== 200) return false;
      const body = String(r.body).trim().toLowerCase();
      return body !== "" && !body.includes("<html") && !body.includes("<!doctype");
    })
    .map((r) => r.path);
  const secrets = exposed.filter((p) => SECRET_MARKERS.some((m) => p.includes(m)));
  const has = exposed.length > 0;
  return result(
    "sensitive_files",
    has ? "fail" : "pass",
    has ? 0 : 6,
    6,
    !has ? "low" : secrets.length > 0 ? "critical" : "high",
    has ? { exposed } : [],
    has ? `Fichier(s) sensible(s) accessible(s) publiquement : ${exposed.join(", ")}` : "Aucun fichier sensible exposé publiquement",
  );
}

export function scoreDirectoryListing(responses) {
  if (responses.length === 0) {
    return result("directory_listing", "skip", 0, 2, "info", { probed: 0 }, "Aucune sonde n'a abouti — résultat non concluant, le site n'a pas répondu");
  }
  const issues = responses
    .filter((r) => r.code === 200 && /Index of \/|<title>Index of/i.test(String(r.body)))
    .map((r) => ({ path: r.url, listing_enabled: true }));
  return result(
    "directory_listing",
    issues.length === 0 ? "pass" : "fail",
    issues.length === 0 ? 2 : 0,
    2,
    "medium",
    issues,
    issues.length === 0 ? "Le listage des répertoires est désactivé" : `Le listage des répertoires est activé sur : ${issues.map((i) => i.path).join(", ")}`,
  );
}

export function scoreSsl(daysRemaining, protocol, issuer) {
  const oldTls = /TLSv1(\.0)?$|TLSv1\.1|SSL/i.test(protocol);
  const issues = [];
  if (daysRemaining < 30) {
    issues.push({ issue: `Certificat expire dans ${daysRemaining} jours` });
  }
  if (oldTls) {
    issues.push({ issue: `Protocole TLS obsolète : ${protocol}` });
  }
  let score = daysRemaining < 7 ? 0 : daysRemaining < 30 ? 4 : 8;
  if (oldTls) {
    score = Math.max(0, score - 4);
  }
  return result(
    "ssl",
    score === 8 ? "pass" : score >= 4 ? "warn" : "fail",
    score,
    8,
    daysRemaining < 7 ? "critical" : daysRemaining < 30 ? "high" : "low",
    { ...Object.fromEntries(issues.map((v, i) => [i, v])), days_remaining: daysRemaining, protocol, issuer },
    issues.length === 0 ? "Certificat SSL valide et à jour" : issues.map((i) => i.issue).join(", "),
  );
}

/**
 * @param {{debug: boolean, debugDisplay: boolean, debugLog: boolean, names: {debug: string, debug_display: string, debug_log: string}}} facts
 */
export function scoreDebugMode(facts) {
  const issues = [];
  if (facts.debug) issues.push({ setting: facts.names.debug, value: true });
  if (facts.debugDisplay) issues.push({ setting: facts.names.debug_display, value: true });
  if (facts.debugLog) issues.push({ setting: facts.names.debug_log, value: true, note: `${facts.names.debug_log} est activé — un fichier de log peut être créé` });
  const score = issues.length === 0 ? 5 : facts.debugDisplay ? 0 : 2;
  return result(
    "debug_mode",
    issues.length === 0 ? "pass" : facts.debugDisplay ? "fail" : "warn",
    score,
    5,
    facts.debugDisplay ? "high" : "medium",
    issues,
    issues.length === 0 ? "Mode debug désactivé en production" : "Le mode debug est actif — risque de fuite d'informations",
  );
}

export function scoreFilePermissions(findings) {
  const writable = findings.filter((f) => f.issue === "world_writable").map((f) => f.path);
  const readable = findings.filter((f) => f.issue !== "world_writable").map((f) => f.path);
  const score = Math.max(0, 10 - writable.length * 3 - readable.length * 2);
  return result(
    "file_permissions",
    writable.length ? "fail" : readable.length ? "warn" : "pass",
    score,
    10,
    writable.length ? "high" : readable.length ? "medium" : "low",
    { world_writable: writable, world_readable_secrets: readable },
    writable.length
      ? `${writable.length} chemin(s) accessibles en écriture par tous — retirez le bit d'écriture « autres » (chmod o-w)`
      : readable.length
        ? `${readable.length} fichier(s) de configuration lisibles par tous — restreignez-les (chmod 640)`
        : "Permissions des fichiers correctes",
  );
}

export function scoreSuspiciousFiles(findings, complete = true) {
  if (!complete && findings.length === 0) {
    return result("suspicious_files", "skip", 0, 15, "info", { complete: false }, "Analyse interrompue avant la fin — résultat non concluant, à relancer");
  }
  const count = findings.length;
  return result(
    "suspicious_files",
    count === 0 ? "pass" : "fail",
    count === 0 ? 15 : 0,
    15,
    count === 0 ? "low" : "critical",
    { count, complete, files: findings.slice(0, 25), truncated: count > 25 },
    count === 0
      ? "Aucun fichier exécutable suspect dans les répertoires de données"
      : `${count} fichier(s) exécutables trouvés là où seules des données sont attendues — inspection humaine requise avant toute autre action`,
  );
}

export function scoreConfigFile(path, present, served, insidePublic, worldReadable) {
  if (!present) {
    return result("config_file", "pass", 5, 5, "low", { path, present: false }, "Aucun fichier de configuration sur disque — configuration fournie par l'environnement");
  }
  const issues = [];
  let score = 5;
  if (served) {
    issues.push("servi par le serveur web");
    score = 0;
  }
  if (insidePublic) {
    issues.push("situé dans la racine web");
    score = Math.min(score, 2);
  }
  if (worldReadable) {
    issues.push("lisible par tous les utilisateurs du système");
    score = Math.min(score, 3);
  }
  return result(
    "config_file",
    served ? "fail" : issues.length ? "warn" : "pass",
    score,
    5,
    served ? "critical" : issues.length ? "medium" : "low",
    { path, present: true, served_over_http: served, inside_public_root: insidePublic, world_readable: worldReadable },
    issues.length === 0 ? "Fichier de configuration correctement protégé" : `Fichier de configuration exposé : ${issues.join(", ")}`,
  );
}

/**
 * Fin de support des branches de Node.js (calendrier officiel). Les branches impaires ne
 * sont jamais LTS et meurent six mois après leur sortie.
 */
export const NODE_EOL = {
  16: "2023-09-11", 17: "2022-06-01", 18: "2025-04-30", 19: "2023-06-01", 20: "2026-04-30",
  21: "2024-06-01", 22: "2027-04-30", 23: "2025-06-01", 24: "2028-04-30", 25: "2026-06-01", 26: "2029-04-30",
};

/** Le pendant de `PhpVersionScorer` : 5 = support long à venir, 0 = fin de vie depuis longtemps. */
export function scoreRuntimeVersion(version, now = new Date()) {
  const major = Number(String(version).split(".")[0]);
  const known = Object.keys(NODE_EOL).map(Number);
  const eolText = NODE_EOL[major] ?? (major > Math.max(...known) ? null : "1970-01-01");
  const eol = eolText === null ? null : new Date(`${eolText}T00:00:00Z`);
  const monthsLeft = eol === null ? Infinity : (eol.getTime() - now.getTime()) / (30.44 * 86_400_000);
  const isEol = monthsLeft <= 0;
  const score = monthsLeft > 12 ? 5 : monthsLeft > 0 ? 4 : monthsLeft > -6 ? 1 : 0;
  return result(
    "runtime_version",
    score >= 4 ? "pass" : score >= 1 ? "warn" : "fail",
    score,
    5,
    score === 0 ? "critical" : isEol ? "high" : "low",
    { runtime: "node", version, eol: isEol, eol_date: eolText },
    isEol
      ? `Node.js ${version} est en fin de vie (plus de correctifs de sécurité) — migrez vers une version LTS supportée`
      : score === 5
        ? "Version de Node.js supportée"
        : `Node.js ${version} — fin de support dans moins d'un an, migration à prévoir`,
  );
}

export function calculateScore(results) {
  let total = 0;
  let max = 0;
  for (const r of results) {
    if (["pass", "warn", "fail"].includes(r.status)) {
      total += r.score;
      max += r.maxScore;
    }
  }
  const score = max > 0 ? Math.round((total / max) * 100) : 0;
  const label = score >= 90 ? "excellent" : score >= 75 ? "good" : score >= 50 ? "average" : "critical";
  return { score, label };
}

/** Jumeau de `ScanAggregator::aggregate` — y compris les sévérités des checks réussis, comptées en `low`. */
export function aggregate(results) {
  const counts = { checks_passed: 0, checks_warned: 0, checks_failed: 0, checks_skipped: 0, critical_issues: 0, high_issues: 0, medium_issues: 0, low_issues: 0 };
  const details = [];
  const vulnerabilities = [];
  for (const r of results) {
    if (r.status === "pass") counts.checks_passed++;
    else if (r.status === "warn") counts.checks_warned++;
    else if (r.status === "fail") counts.checks_failed++;
    else counts.checks_skipped++;

    if (r.severity === "critical") counts.critical_issues++;
    else if (r.severity === "high") counts.high_issues++;
    else if (r.severity === "medium") counts.medium_issues++;
    else counts.low_issues++;

    details.push({ name: r.name, status: r.status, score: r.score, max_score: r.maxScore, severity: r.severity, details: r.details, recommendation: r.recommendation });
    vulnerabilities.push(...(r.vulnerabilities ?? []));
  }
  return { ...counts, details, vulnerabilities };
}

export const warrantsAlert = (score, critical) => score < 50 || critical > 0;
export const alertSeverity = (critical) => (critical > 0 ? "critical" : "high");
