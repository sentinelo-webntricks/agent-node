import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Agent } from "./agent.js";
import { tagFor, plan } from "./backup/retention.js";
import { fromPackageLock, fromPnpmLock, fromYarnLock } from "./platform/inventory.js";
import { scoreRuntimeVersion } from "./scan/checks.js";
import { loadSettings } from "./settings.js";

function makeAgent(extraEnv = {}) {
  const root = mkdtempSync(join(tmpdir(), "agent-"));
  writeFileSync(join(root, "package.json"), JSON.stringify({ name: "boutique", dependencies: { next: "^14.2.3", express: "^4" } }));
  const agent = new Agent(loadSettings({ projectRoot: root, env: { SENTINELO_SECRET: "test-secret-0123456789abcdef", ...extraEnv } }));
  return agent;
}

const call = (agent, route, { key, body = {}, ip = "10.0.0.1" } = {}) =>
  agent.handle({ route, method: "POST", ip, headers: key ? { "x-sentinelo-api-key": key } : {}, query: new URLSearchParams(), body });

test("un agent non enrôlé refuse tout, `health` compris, en NOT_CONFIGURED", async () => {
  const res = await call(makeAgent(), "health");
  assert.equal(res.status, 403);
  assert.equal(res.body.error.code, "NOT_CONFIGURED");
  assert.equal(res.body.meta.application, "nextjs");
});

test("authentification, routes refusées en 501 et routes inconnues en 404", async () => {
  const agent = makeAgent();
  agent.config.set("api_key", "la-cle");
  assert.equal((await call(agent, "health", { key: "mauvaise" })).body.error.code, "UNAUTHORIZED");

  const health = await call(agent, "health", { key: "la-cle" });
  assert.equal(health.status, 200);
  assert.equal(health.body.data.supports_package_updates, false);
  assert.equal(health.body.data.php_version, null);

  assert.equal((await call(agent, "updates/apply", { key: "la-cle", body: { updates: [{ type: "package", slug: "next", version: "15" }] } })).status, 501);
  assert.equal((await call(agent, "hardening", { key: "la-cle" })).status, 501);
  assert.equal((await call(agent, "nimporte", { key: "la-cle" })).status, 404);
});

test("la clé API est chiffrée au repos et survit à une relecture", () => {
  const agent = makeAgent();
  agent.config.set("api_key", "secret-de-site");
  const raw = JSON.parse(readFileSync(join(agent.settings.dataDir, "config.json"), "utf8"));
  assert.equal(raw.api_key.secret, true);
  assert.ok(!raw.api_key.value.includes("secret-de-site"));
  assert.equal(agent.config.get("api_key"), "secret-de-site");
});

test("cloud-config : forme plate validée, et ce qui manque est nommé", async () => {
  const agent = makeAgent();
  agent.config.set("api_key", "k");
  const refused = await call(agent, "cloud-config", { key: "k", body: { key_id: "a" } });
  assert.equal(refused.status, 400);
  assert.match(refused.body.error.message, /app_key, bucket_name/);
  const ok = await call(agent, "cloud-config", { key: "k", body: { key_id: "a", app_key: "b", bucket_name: "c", endpoint: "http://s3:9000" } });
  assert.equal(ok.body.data.configured, true);
  assert.equal(agent.storage().objectUrl("x"), "http://s3:9000/c/x");
});

test("backup/run refuse un type inconnu en 400, sans laisser de ligne en échec", async () => {
  const agent = makeAgent();
  agent.config.set("api_key", "k");
  const res = await call(agent, "backup/run", { key: "k", body: { type: "hourly" } });
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, "VALIDATION_ERROR");
  assert.equal(agent.backups.all().length, 0);
});

test("restore confine le chemin à l'espace du site", async () => {
  const agent = makeAgent();
  agent.config.set("api_key", "k");
  agent.config.set("site_uuid", "aaa");
  const res = await call(agent, "backup/restore", { key: "k", body: { backup_cloud_path: "backups/bbb/daily/x.tar.enc" } });
  assert.equal(res.status, 400);
  assert.match(res.body.error.message, /hors de l'espace/);
});

test("étiquetage GFS et plan de rétention", () => {
  assert.equal(tagFor(new Date("2026-01-01T03:00:00Z")).tag, "daily,monthly,yearly");
  assert.equal(tagFor(new Date("2026-11-01T03:00:00Z")).tag, "daily,weekly,monthly");
  assert.equal(tagFor(new Date("2026-10-28T03:00:00Z")).expires_at, "2026-11-04 03:00:00");
  const backups = Array.from({ length: 10 }, (_, i) => ({ id: i + 1, tags: ["daily"], at: new Date(Date.UTC(2026, 9, 10 + i)) }));
  assert.deepEqual(plan(backups, new Date("2026-10-20T00:00:00Z")).prune.sort((a, b) => a - b), [1, 2, 3]);
});

test("inventaire : les trois formats de verrou", () => {
  const npm = fromPackageLock(JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/next": { version: "14.2.3" }, "node_modules/@scope/x": { version: "1.0.0", dev: true } } }));
  assert.deepEqual(npm.map((p) => `${p.name}@${p.version}`), ["@scope/x@1.0.0", "next@14.2.3"]);

  const pnpm = fromPnpmLock("lockfileVersion: '9.0'\n\npackages:\n\n  next@14.2.3:\n    resolution: {integrity: x}\n\n  '@scope/x@1.0.0(react@18.0.0)':\n    resolution: {}\n");
  assert.deepEqual(pnpm.map((p) => `${p.name}@${p.version}`), ["@scope/x@1.0.0", "next@14.2.3"]);

  const yarn = fromYarnLock('next@^14.2.0, next@^14.2.3:\n  version "14.2.3"\n  resolved "x"\n\n"@scope/x@^1":\n  version "1.0.0"\n');
  assert.deepEqual(yarn.map((p) => `${p.name}@${p.version}`), ["@scope/x@1.0.0", "next@14.2.3"]);
});

test("version de Node : fin de vie notée comme PHP l'est", () => {
  const now = new Date("2026-10-30T00:00:00Z");
  assert.equal(scoreRuntimeVersion("24.11.0", now).score, 5);
  assert.equal(scoreRuntimeVersion("22.12.0", now).score, 4);
  // Fin de vie le 2026-04-30 : « warn » dans les six mois qui suivent, « fail » ensuite.
  assert.equal(scoreRuntimeVersion("20.18.0", new Date("2026-07-01T00:00:00Z")).status, "warn");
  assert.equal(scoreRuntimeVersion("20.18.0", now).status, "fail");
  assert.equal(scoreRuntimeVersion("16.20.0", now).score, 0);
});

