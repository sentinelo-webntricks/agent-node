import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { backupPayload, restorePayload } from "./backup/payloads.js";
import { Envelope } from "./http/envelope.js";
import { AGENT_VERSION } from "./version.js";

/**
 * Le contrat agent ↔ backend, lu dans les fixtures canoniques (`contracts/agent/v1`,
 * copiées par `scripts/sync-contracts.sh`) : un agent dont les clés divergent de celles
 * que le backend analyse continuerait de passer ses propres tests en mentant à la plateforme.
 */

const fixture = (name) => JSON.parse(readFileSync(fileURLToPath(new URL(`../tests/contract/fixtures/v1/${name}`, import.meta.url)), "utf8"));
const keys = (o) => Object.keys(o).sort();

test("le payload de sauvegarde porte exactement les clés du contrat", () => {
  const produced = backupPayload({ id: 1, backup_type: "daily", status: "completed", started_at: "2026-08-08 03:00:03", completed_at: "2026-08-08 03:01:21", file_size_bytes: 10, includes_db: true, steps: [] });
  assert.deepEqual(keys(produced), keys(fixture("backup.completed.json")));
  assert.equal(produced.started_at, "2026-08-08T03:00:03+00:00");
  assert.equal(produced.duration_seconds, 78);
});

test("le payload de restauration porte exactement les clés du contrat", () => {
  assert.deepEqual(keys(restorePayload({ id: 1, scope: "all", status: "completed" })), keys(fixture("restore.completed.json")));
});

test("l'enveloppe : `error` est un objet, `meta` nomme l'application et la version", () => {
  const env = new Envelope({ slug: "nextjs", version: "14.2.3" });
  const error = env.error("CONFLICT", "occupé", 409);
  assert.equal(error.status, 409);
  assert.deepEqual(keys(error.body.error), keys(fixture("envelope.error.json").error));
  assert.equal(error.body.meta.plugin_version, AGENT_VERSION);
  assert.equal(error.body.meta.application, "nextjs");
  assert.match(error.body.meta.timestamp, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$/);
  for (const key of ["plugin_version", "php_version", "timestamp", "execution_time_ms"]) {
    assert.ok(key in env.success({}).body.meta, key);
  }
});

test("la version annoncée est celle du paquet publié", () => {
  const pkg = JSON.parse(readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"));
  assert.equal(AGENT_VERSION, pkg.version);
});
