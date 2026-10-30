import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { TarWriter, extract, header, list, readEntry, safeEntryPath } from "./tar.js";

test("l'en-tête reproduit celui de TarWriter (PHP) au champ près", () => {
  const h = header("database.sql", 1234, "0", 0);
  assert.equal(h.length, 512);
  assert.equal(h.toString("latin1", 100, 108), "0000644\0");
  assert.equal(h.toString("latin1", 124, 136), "00000002322 ");
  assert.equal(h.toString("latin1", 257, 265), "ustar\u000000");
  // Somme : en-tête lu avec le champ de somme remplacé par 8 espaces.
  const copy = Buffer.from(h);
  copy.write("        ", 148, "latin1");
  const sum = copy.reduce((s, b) => s + b, 0);
  assert.equal(h.toString("latin1", 148, 156), `${sum.toString(8).padStart(6, "0")}\0 `);
});

test("aller-retour : base d'abord, nom long, manifeste en dernier", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tar-"));
  writeFileSync(join(dir, "db.sql"), "SELECT 1;\n");
  const longName = `files/source/${"tres-long-dossier/".repeat(8)}fichier.ts`;
  writeFileSync(join(dir, "f"), "x".repeat(1000));

  const tar = new TarWriter(join(dir, "a.tar"));
  await tar.addFile(join(dir, "db.sql"), "database.sql", 10);
  await tar.addFile(join(dir, "f"), longName, 1000);
  await tar.addBuffer("manifest.json", '{"ok":true}');
  await tar.seal();

  assert.deepEqual(await list(join(dir, "a.tar")), ["database.sql", longName, "manifest.json"]);
  assert.equal((await readEntry(join(dir, "a.tar"), "manifest.json")).toString(), '{"ok":true}');

  await extract(join(dir, "a.tar"), join(dir, "out"));
  assert.equal(readFileSync(join(dir, "out", longName), "utf8"), "x".repeat(1000));
});

test("un fichier qui a rétréci depuis le plan ne décale pas la suite", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tar-"));
  writeFileSync(join(dir, "small"), "abc");
  writeFileSync(join(dir, "next"), "suite");
  const tar = new TarWriter(join(dir, "a.tar"));
  await tar.addFile(join(dir, "small"), "small", 10);
  await tar.addFile(join(dir, "next"), "next", 5);
  await tar.seal();
  assert.equal((await readEntry(join(dir, "a.tar"), "next")).toString(), "suite");
});

test("refuse les entrées qui sortent de la cible", () => {
  const root = mkdtempSync(join(tmpdir(), "tar-"));
  mkdirSync(join(root, "a"));
  assert.throws(() => safeEntryPath(root, "../etc/passwd"), /hors périmètre/);
  assert.throws(() => safeEntryPath(root, "/etc/passwd"), /hors périmètre/);
  assert.throws(() => safeEntryPath(root, "a/../../x"), /hors périmètre/);
  assert.ok(safeEntryPath(root, "a/b.txt").startsWith(root));
});
