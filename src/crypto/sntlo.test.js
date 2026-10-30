import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { CHUNK_BYTES, decryptFile, decryptString, deriveKey, encryptFile, encryptString } from "./sntlo.js";

/**
 * La compatibilité se prouve CROISÉE : les fixtures `php-*` sont produites par
 * l'implémentation PHP de référence (`tests/make-php-crypto-fixtures.php`, même secret),
 * et ce test écrit `node-*` que ce même script déchiffre au passage suivant.
 */

const FIXTURES = fileURLToPath(new URL("../../tests/fixtures/", import.meta.url));
const SECRET = "fixture-secret-0123456789abcdef";
const key = deriveKey({ SENTINELO_SECRET: SECRET });
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

test("déchiffre un fichier chiffré par l'agent PHP", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sntlo-"));
  const out = join(dir, "plain.bin");
  await decryptFile(key, join(FIXTURES, "php-encrypted.bin.enc"), out);
  assert.equal(sha256(readFileSync(out)), readFileSync(join(FIXTURES, "php-plain.sha256"), "utf8").trim());
});

test("déchiffre une chaîne chiffrée par l'agent PHP", () => {
  assert.equal(decryptString(key, readFileSync(join(FIXTURES, "php-string.txt"), "utf8")), '{"api_key":"clé-é-🙂"}');
});

test("produit les fixtures que l'agent PHP déchiffrera", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sntlo-"));
  const plain = Buffer.alloc(CHUNK_BYTES + 5, 7);
  writeFileSync(join(dir, "p.bin"), plain);
  await encryptFile(key, join(dir, "p.bin"), join(FIXTURES, "node-encrypted.bin.enc"));
  writeFileSync(join(FIXTURES, "node-string.txt"), encryptString(key, "depuis Node"));
  writeFileSync(join(FIXTURES, "node-plain.sha256"), sha256(plain));
});

test("aller-retour, y compris un fichier vide", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sntlo-"));
  for (const size of [0, 1, CHUNK_BYTES, CHUNK_BYTES * 2 + 3]) {
    const plain = Buffer.alloc(size, size % 251);
    writeFileSync(join(dir, "in"), plain);
    await encryptFile(key, join(dir, "in"), join(dir, "enc"));
    await decryptFile(key, join(dir, "enc"), join(dir, "out"));
    assert.ok(readFileSync(join(dir, "out")).equals(plain), `taille ${size}`);
  }
});

test("refuse une archive tronquée ou altérée", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sntlo-"));
  writeFileSync(join(dir, "in"), Buffer.alloc(CHUNK_BYTES + 10, 1));
  await encryptFile(key, join(dir, "in"), join(dir, "enc"));
  const enc = readFileSync(join(dir, "enc"));

  // Sans le bloc terminal : chaque bloc restant se vérifie, mais la fin manque.
  writeFileSync(join(dir, "short"), enc.subarray(0, enc.length - (4 + 12 + 16)));
  await assert.rejects(decryptFile(key, join(dir, "short"), join(dir, "o1")), /tronquée/);

  const flipped = Buffer.from(enc);
  flipped[100] ^= 1;
  writeFileSync(join(dir, "bad"), flipped);
  await assert.rejects(decryptFile(key, join(dir, "bad"), join(dir, "o2")), /refusé au bloc 0/);
});

test("refuse les secrets trop courts ou livrés par défaut", () => {
  assert.throws(() => deriveKey({}), /Aucun secret utilisable/);
  assert.throws(() => deriveKey({ SENTINELO_SECRET: "short" }), /Aucun secret utilisable/);
  assert.throws(() => deriveKey({ APP_SECRET: "ThisTokenIsNotSoSecretChangeIt" }), /Aucun secret utilisable/);
});

test("la même valeur donne la même clé, quel que soit le nom de la variable", () => {
  assert.ok(deriveKey({ SENTINELO_SECRET: SECRET }).equals(deriveKey({ APP_SECRET: SECRET })));
  const raw = Buffer.alloc(32, 9);
  assert.ok(deriveKey({ APP_KEY: `base64:${raw.toString("base64")}` }).equals(deriveKey({ SENTINELO_SECRET: raw.toString("latin1") })));
});
