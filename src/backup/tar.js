import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, open } from "node:fs/promises";
import { dirname, join, normalize, sep } from "node:path";
import { pipeline } from "node:stream/promises";

/**
 * Le tar des sauvegardes — jumeau de `AgentCore\Backup\TarWriter` / `TarReader`.
 *
 * ustar non compressé, blocs de 512 octets, en-tête identique au PHP (mode `0000644`,
 * uid/gid nuls, mtime = l'heure d'écriture). Un nom de plus de 100 octets est précédé d'une
 * entrée GNU `././@LongLink` de type `L` — le champ `prefix` d'ustar exige un `/` bien
 * placé, ce qu'un nom de fichier long seul ne permet pas.
 *
 * La fin d'archive (deux blocs nuls) n'est écrite qu'au SCELLEMENT : tant qu'elle manque,
 * l'archive est inachevée par construction.
 */

const BLOCK = 512;
const NAME_MAX = 100;

function octal(value, width) {
  return value.toString(8).padStart(width, "0");
}

/** En-tête ustar de 512 octets, somme de contrôle comprise. */
export function header(name, size, type, mtime = Math.floor(Date.now() / 1000)) {
  const buf = Buffer.alloc(BLOCK, 0);
  // Borné en OCTETS : sans la longueur, un nom long déborderait sur les champs suivants.
  buf.write(name, 0, NAME_MAX, "utf8");
  buf.write("0000644\0", 100, "latin1");
  buf.write("0000000\0", 108, "latin1");
  buf.write("0000000\0", 116, "latin1");
  buf.write(`${octal(size, 11)} `, 124, "latin1");
  buf.write(`${octal(mtime, 11)} `, 136, "latin1");
  buf.write("        ", 148, "latin1");
  buf.write(type, 156, "latin1");
  buf.write("ustar\0", 257, "latin1");
  buf.write("00", 263, "latin1");
  let sum = 0;
  for (const byte of buf) {
    sum += byte;
  }
  buf.write(`${octal(sum, 6)}\0 `, 148, "latin1");
  return buf;
}

function padding(size) {
  const rest = size % BLOCK;
  return rest === 0 ? Buffer.alloc(0) : Buffer.alloc(BLOCK - rest, 0);
}

export class TarWriter {
  /** @param {string} path */
  constructor(path) {
    this.path = path;
    this.stream = createWriteStream(path);
    this.bytes = 0;
  }

  async write(buffer) {
    if (!this.stream.write(buffer)) {
      await new Promise((r) => this.stream.once("drain", r));
    }
    this.bytes += buffer.length;
  }

  async entryHeader(name, size) {
    const clean = name.replace(/\\/g, "/").replace(/^\/+/, "");
    if (Buffer.byteLength(clean) > NAME_MAX) {
      const long = Buffer.from(`${clean}\0`, "utf8");
      await this.write(header("././@LongLink", long.length, "L"));
      await this.write(Buffer.concat([long, padding(long.length)]));
    }
    await this.write(header(clean, size, "0"));
  }

  /** Ajoute un fichier du disque sous `entryName`. `size` est celle relevée au plan. */
  async addFile(source, entryName, size) {
    await this.entryHeader(entryName, size);
    let written = 0;
    const input = await open(source, "r");
    try {
      const chunk = Buffer.alloc(1024 * BLOCK);
      while (written < size) {
        const { bytesRead } = await input.read(chunk, 0, Math.min(chunk.length, size - written), null);
        if (bytesRead === 0) {
          break;
        }
        await this.write(chunk.subarray(0, bytesRead));
        written += bytesRead;
      }
    } finally {
      await input.close();
    }
    // Un fichier qui a rétréci depuis le plan : on complète par des zéros plutôt que de
    // décaler toutes les entrées suivantes, ce qui rendrait la suite de l'archive illisible.
    if (written < size) {
      await this.write(Buffer.alloc(size - written, 0));
    }
    await this.write(padding(size));
  }

  async addBuffer(entryName, data) {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
    await this.entryHeader(entryName, buffer.length);
    await this.write(buffer);
    await this.write(padding(buffer.length));
  }

  async seal() {
    await this.write(Buffer.alloc(BLOCK * 2, 0));
    await new Promise((resolvePromise, reject) => {
      this.stream.end((e) => (e ? reject(e) : resolvePromise()));
    });
  }

  async abort() {
    await new Promise((r) => this.stream.end(r));
  }
}

/** Le contenu d'une archive : les entrées dans l'ordre. */
async function* entries(path) {
  const handle = await open(path, "r");
  try {
    let offset = 0;
    let longName = null;
    const head = Buffer.alloc(BLOCK);
    for (;;) {
      const { bytesRead } = await handle.read(head, 0, BLOCK, offset);
      if (bytesRead < BLOCK || head.every((b) => b === 0)) {
        return;
      }
      if (head.toString("latin1", 257, 262) !== "ustar") {
        throw new Error("Archive tar illisible (en-tête ustar absent).");
      }
      const size = parseInt(head.toString("latin1", 124, 136).replace(/\0.*$/, "").trim() || "0", 8);
      const type = head.toString("latin1", 156, 157);
      let name = head.toString("utf8", 0, 100).replace(/\0.*$/s, "");
      const prefix = head.toString("utf8", 345, 500).replace(/\0.*$/s, "");
      if (prefix) {
        name = `${prefix}/${name}`;
      }
      const dataOffset = offset + BLOCK;
      offset = dataOffset + Math.ceil(size / BLOCK) * BLOCK;

      if (type === "L") {
        const buf = Buffer.alloc(size);
        await handle.read(buf, 0, size, dataOffset);
        longName = buf.toString("utf8").replace(/\0.*$/s, "");
        continue;
      }
      if (longName !== null) {
        name = longName;
        longName = null;
      }
      if (type !== "0" && type !== "\0" && type !== "" && type !== "5") {
        continue;
      }
      yield { name, size, type: type === "5" ? "dir" : "file", dataOffset };
    }
  } finally {
    await handle.close();
  }
}

/** Refuse `..`, les chemins absolus et les lettres de lecteur : une archive ne sort pas de sa cible. */
export function safeEntryPath(root, name) {
  const clean = name.replace(/\\/g, "/");
  if (clean.startsWith("/") || /^[A-Za-z]:/.test(clean) || clean.split("/").includes("..")) {
    throw new Error(`Entrée d'archive hors périmètre refusée : ${name}`);
  }
  const target = normalize(join(root, clean));
  if (target !== root && !target.startsWith(root.endsWith(sep) ? root : root + sep)) {
    throw new Error(`Entrée d'archive hors périmètre refusée : ${name}`);
  }
  return target;
}

/** Extrait toute l'archive sous `root`. */
export async function extract(path, root) {
  await mkdir(root, { recursive: true });
  let count = 0;
  for await (const entry of entries(path)) {
    const target = safeEntryPath(root, entry.name);
    if (entry.type === "dir") {
      await mkdir(target, { recursive: true });
      continue;
    }
    await mkdir(dirname(target), { recursive: true });
    if (entry.size === 0) {
      await (await open(target, "w")).close();
    } else {
      await pipeline(createReadStream(path, { start: entry.dataOffset, end: entry.dataOffset + entry.size - 1 }), createWriteStream(target));
    }
    count++;
  }
  return count;
}

/** Lit une entrée entière en mémoire (manifest.json, index.json), ou `null`. */
export async function readEntry(path, wanted) {
  for await (const entry of entries(path)) {
    if (entry.name === wanted && entry.type === "file") {
      const handle = await open(path, "r");
      try {
        const buf = Buffer.alloc(entry.size);
        await handle.read(buf, 0, entry.size, entry.dataOffset);
        return buf;
      } finally {
        await handle.close();
      }
    }
  }
  return null;
}

/** Les noms d'entrées, pour les tests et le diagnostic. */
export async function list(path) {
  const names = [];
  for await (const entry of entries(path)) {
    names.push(entry.name);
  }
  return names;
}
