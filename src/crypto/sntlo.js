import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { open } from "node:fs/promises";

/**
 * Le format `SNTLO\x01` — octet pour octet celui de l'agent Composer
 * (`agents/composer/src/Adapter/OpenSslCrypto.php`).
 *
 * ## Pourquoi CE format et pas `SENTFEN2`
 *
 * Le backend ne déchiffre jamais une archive : il compare une taille et une empreinte. Le
 * choix ne regarde donc que l'agent, et celui-ci n'a besoin que de `node:crypto` — AES-GCM
 * et HKDF y sont natifs, là où `SENTFEN2` demande libsodium et BLAKE2b. Un format déjà
 * produit par la flotte vaut mieux qu'un troisième.
 *
 * ## Le fichier
 *
 *     "SNTLO\x01" puis, par bloc de 1 Mio en clair :
 *     [u32 BE longueur du chiffré][iv 12][tag 16][chiffré]
 *
 * Les données authentifiées d'un bloc sont `"SNTLO\x01"` suivi de son index **en chiffres
 * ASCII décimaux** — PHP concatène l'entier à la chaîne (`self::MAGIC . $index`), et un
 * entier binaire ici rendrait chaque archive illisible par l'autre implémentation. La fin
 * est un bloc VIDE authentifié sous l'index suivant : sans lui, tronquer le fichier
 * produirait une archive plus courte dont chaque bloc restant se vérifie encore.
 *
 * ## La chaîne (secrets au repos)
 *
 *     base64("SNTLO\x01" ‖ iv ‖ tag ‖ chiffré), données authentifiées = "SNTLO\x01"
 */

export const MAGIC = Buffer.from("SNTLO\x01", "latin1");
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
export const CHUNK_BYTES = 1048576;
const HKDF_INFO = "sentinelo-agent-backup-v1";

const PLACEHOLDERS = ["thistokenisnotsosecretchangeit", "changeme", "secret", "base64:", "somesecret"];

export class CryptoError extends Error {
  constructor(message) {
    super(message);
    this.name = "CryptoError";
  }
}

/**
 * La clé, dérivée du premier secret utilisable — même ordre et mêmes refus que
 * `OpenSslCrypto::key()`. `APP_SECRET` / `APP_KEY` n'existent pas dans un projet Node
 * ordinaire ; ils restent lus pour qu'une même valeur donne la même clé partout.
 *
 * @param {Record<string, string|undefined>} env
 */
export function deriveKey(env) {
  for (const name of ["SENTINELO_SECRET", "APP_SECRET", "APP_KEY"]) {
    let material = Buffer.from(String(env[name] ?? ""), "utf8");
    const asText = material.toString("utf8");
    if (asText.startsWith("base64:")) {
      material = Buffer.from(asText.slice(7), "base64");
    }
    if (isUsable(material)) {
      return Buffer.from(hkdfSync("sha256", material, Buffer.alloc(0), HKDF_INFO, 32));
    }
  }
  throw new CryptoError(
    "Aucun secret utilisable : définissez SENTINELO_SECRET avec au moins 16 caractères " +
      "(`sentinelo-agent init` en génère un). L'agent refuse de chiffrer avec une clé par défaut, " +
      "qui serait identique sur toutes les installations.",
  );
}

function isUsable(material) {
  if (material.length < 16) {
    return false;
  }
  const normalised = material.toString("utf8").trim().toLowerCase();
  return !PLACEHOLDERS.includes(normalised);
}

function aad(index) {
  return Buffer.concat([MAGIC, Buffer.from(String(index), "latin1")]);
}

function seal(key, plain, associated) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LENGTH });
  cipher.setAAD(associated);
  const body = Buffer.concat([cipher.update(plain), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), body };
}

function unseal(key, iv, tag, body, associated) {
  const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LENGTH });
  decipher.setAAD(associated);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

/** @param {Buffer} key @param {string|Buffer} plaintext */
export function encryptString(key, plaintext) {
  const { iv, tag, body } = seal(key, Buffer.from(plaintext), MAGIC);
  return Buffer.concat([MAGIC, iv, tag, body]).toString("base64");
}

/** @param {Buffer} key @param {string} encoded @returns {string} */
export function decryptString(key, encoded) {
  const raw = Buffer.from(String(encoded), "base64");
  const header = MAGIC.length + IV_LENGTH + TAG_LENGTH;
  if (raw.length < header || !raw.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new CryptoError("Texte chiffré illisible ou produit par une autre implémentation");
  }
  try {
    return unseal(
      key,
      raw.subarray(MAGIC.length, MAGIC.length + IV_LENGTH),
      raw.subarray(MAGIC.length + IV_LENGTH, header),
      raw.subarray(header),
      MAGIC,
    ).toString("utf8");
  } catch {
    throw new CryptoError("Déchiffrement refusé : contenu altéré ou clé différente");
  }
}

/**
 * Écrit tout, ou lève. Une écriture courte qu'on ignore produit une archive tronquée dont
 * l'empreinte — calculée ensuite sur le fichier tronqué — correspond à ce qui est envoyé :
 * la sauvegarde passe pour vérifiée et le dégât ne se voit qu'à la restauration.
 */
async function writeAll(handle, buffer, destination) {
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesWritten } = await handle.write(buffer, offset, buffer.length - offset);
    if (bytesWritten <= 0) {
      throw new CryptoError(`Écriture incomplète dans ${destination} — disque plein ?`);
    }
    offset += bytesWritten;
  }
}

/** Lit jusqu'à `size` octets — moins seulement en fin de fichier. */
async function readUpTo(handle, size) {
  const buffer = Buffer.alloc(size);
  let filled = 0;
  while (filled < size) {
    const { bytesRead } = await handle.read(buffer, filled, size - filled, null);
    if (bytesRead === 0) {
      break;
    }
    filled += bytesRead;
  }
  return buffer.subarray(0, filled);
}

/** @param {Buffer} key @param {string} source @param {string} destination */
export async function encryptFile(key, source, destination) {
  const input = await open(source, "r");
  const output = await open(destination, "w");
  try {
    await writeAll(output, MAGIC, destination);
    let index = 0;
    for (;;) {
      const plain = await readUpTo(input, CHUNK_BYTES);
      if (plain.length === 0) {
        break;
      }
      await writeChunk(output, key, plain, index++, destination);
    }
    await writeChunk(output, key, Buffer.alloc(0), index, destination);
  } finally {
    await input.close();
    await output.close();
  }
}

async function writeChunk(output, key, plain, index, destination) {
  const { iv, tag, body } = seal(key, plain, aad(index));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(body.length, 0);
  await writeAll(output, Buffer.concat([length, iv, tag, body]), destination);
}

/** @param {Buffer} key @param {string} source @param {string} destination */
export async function decryptFile(key, source, destination) {
  const input = await open(source, "r");
  const output = await open(destination, "w");
  try {
    const head = await readUpTo(input, MAGIC.length);
    if (!head.equals(MAGIC)) {
      throw new CryptoError("Archive non produite par cet agent (en-tête inattendu)");
    }
    for (let index = 0; ; index++) {
      const header = await readUpTo(input, 4);
      if (header.length < 4) {
        throw new CryptoError("Archive tronquée : marqueur de fin absent");
      }
      const length = header.readUInt32BE(0);
      const iv = await readUpTo(input, IV_LENGTH);
      const tag = await readUpTo(input, TAG_LENGTH);
      const body = length > 0 ? await readUpTo(input, length) : Buffer.alloc(0);
      if (iv.length !== IV_LENGTH || tag.length !== TAG_LENGTH || body.length !== length) {
        throw new CryptoError("Archive tronquée pendant le déchiffrement");
      }
      let plain;
      try {
        plain = unseal(key, iv, tag, body, aad(index));
      } catch {
        throw new CryptoError(
          `Déchiffrement refusé au bloc ${index} : archive altérée, réordonnée, ou clé différente`,
        );
      }
      if (plain.length === 0) {
        return;
      }
      await writeAll(output, plain, destination);
    }
  } finally {
    await input.close();
    await output.close();
  }
}
