import { createHash, createHmac } from "node:crypto";
import { open, stat } from "node:fs/promises";

import { excerpt, request } from "../support/http.js";

/**
 * Le dépôt d'objets (Backblaze B2, R2, S3, RustFS…) en SigV4 — jumeau de
 * `AgentCore\Storage\S3Signer`, `S3Endpoint`, `MultipartUpload` et `StorageError`.
 *
 * ## Différence voulue avec l'agent Composer
 *
 * Celui-ci refuse toute archive de 100 Mio et plus, faute de reprise. Un démon n'a pas de
 * limite de temps PHP : l'envoi multipart est donc fait dès 20 Mio, par parties de
 * 10 Mio, chacune retentée sur un refus transitoire.
 */

export const DEFAULT_REGION = "us-west-004";
export const PART_SIZE = 10 * 1024 * 1024;
export const MULTIPART_FROM = 20 * 1024 * 1024;
const TIMEOUT = 900;
const RETRYABLE = [408, 425, 429, 500, 502, 503, 504];

/** Un silence ou un refus passager du dépôt : on retente. */
export class TransientStorageFailure extends Error {
  constructor(message) {
    super(message);
    this.name = "TransientStorageFailure";
  }
}

export class StorageRefusal extends Error {
  constructor(message) {
    super(message);
    this.name = "StorageRefusal";
  }
}

const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const hmac = (key, data) => createHmac("sha256", key).update(data).digest();

export function amzDate(date = new Date()) {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/** RFC 3986 — `encodeURIComponent` laisse passer `!'()*`, que `rawurlencode` encode. */
function rfc3986(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function canonicalQuery(search) {
  const query = search.startsWith("?") ? search.slice(1) : search;
  if (query === "") {
    return "";
  }
  return query
    .split("&")
    .filter((p) => p !== "")
    .map((part) => {
      const eq = part.indexOf("=");
      const name = eq === -1 ? part : part.slice(0, eq);
      const value = eq === -1 ? "" : part.slice(eq + 1);
      return [rfc3986(safeDecode(name)), rfc3986(safeDecode(value))];
    })
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
    .map(([n, v]) => `${n}=${v}`)
    .join("&");
}

/**
 * L'en-tête `Authorization`, calculé sur les en-têtes MÊMES qui partiront — la date est
 * lue dans `x-amz-date`, jamais régénérée (la cause d'un 403 intermittent côté PHP).
 */
export function authorization({ accessKeyId, secretAccessKey, region }, method, url, headers, payloadHash) {
  const target = new URL(url);
  const normalized = Object.entries(headers)
    .map(([k, v]) => [k.toLowerCase().trim(), String(v).trim()])
    .sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const date = normalized.find(([k]) => k === "x-amz-date")?.[1];
  if (!date) {
    throw new Error("La signature exige un en-tête x-amz-date.");
  }
  const shortDate = date.slice(0, 8);
  const scope = `${shortDate}/${region}/s3/aws4_request`;
  const canonicalHeaders = normalized.map(([k, v]) => `${k}:${v}\n`).join("");
  const signedHeaders = normalized.map(([k]) => k).join(";");
  const canonicalRequest = [method, target.pathname || "/", canonicalQuery(target.search), canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const stringToSign = ["AWS4-HMAC-SHA256", date, scope, sha256(canonicalRequest)].join("\n");
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${secretAccessKey}`, shortDate), region), "s3"), "aws4_request");
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex");
  return `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

/** Ce que le dépôt a dit, pas seulement son code : `Code : Message` du corps XML/JSON. */
export function describeRefusal(response) {
  if (response.status === 0) {
    return `transport : ${response.error}`;
  }
  const text = response.body.toString("utf8");
  const code = /<Code>([^<]+)<\/Code>/.exec(text)?.[1];
  const message = /<Message>([^<]+)<\/Message>/.exec(text)?.[1];
  if (code || message) {
    return `HTTP ${response.status} — ${[code, message].filter(Boolean).join(" : ")}`.slice(0, 300);
  }
  if (/<html/i.test(text)) {
    return `HTTP ${response.status} — réponse HTML (proxy ou pare-feu ?)`;
  }
  return `HTTP ${response.status}${text ? ` — ${excerpt(response)}` : ""}`;
}

export class ObjectStorage {
  /**
   * @param {string} provider
   * @param {Record<string, string>} credentials tels que `cloud-config` les a rangés
   */
  constructor(provider, credentials) {
    const str = (k) => (typeof credentials[k] === "string" ? credentials[k].trim() : credentials[k] === undefined || credentials[k] === null ? "" : String(credentials[k]).trim());
    this.region = str("region") || DEFAULT_REGION;
    this.bucket = str("bucket_name") || str("bucket");
    this.accessKeyId = str("key_id") || str("access_key_id");
    this.secretAccessKey = str("app_key") || str("secret_access_key");
    this.provider = provider;

    let base = str("endpoint");
    if (base !== "") {
      if (!/^https?:\/\//.test(base)) {
        base = `https://${base}`;
      }
      base = base.replace(/\/+$/, "");
    } else if (provider === "backblaze_b2") {
      base = `https://s3.${this.region}.backblazeb2.com`;
    } else if (provider === "cloudflare_r2") {
      base = `https://${str("account_id")}.r2.cloudflarestorage.com`;
    } else {
      base = "https://s3.amazonaws.com";
    }
    this.baseUrl = base;

    if (!this.accessKeyId || !this.secretAccessKey || !this.bucket) {
      throw new StorageRefusal("Cloud credentials not configured");
    }
  }

  /** URL path-style : le style « virtual host » rend un 301 silencieux chez B2. */
  objectUrl(key) {
    return `${this.baseUrl}/${this.bucket}/${key.replace(/^\/+/, "")}`;
  }

  headers(method, url, payloadHash, extra = {}) {
    const headers = { Host: new URL(url).host, "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate(), ...extra };
    headers.Authorization = authorization(this, method, url, headers, payloadHash);
    return headers;
  }

  async send(method, url, payloadHash, extra, options = {}) {
    const response = await request(method, url, { headers: this.headers(method, url, payloadHash, extra), timeout: TIMEOUT, ...options });
    if (response.status === 0 || RETRYABLE.includes(response.status)) {
      throw new TransientStorageFailure(describeRefusal(response));
    }
    return response;
  }

  /** Une requête retentée sur échec passager — 3 essais, attente croissante. */
  async withRetry(fn, attempts = 3) {
    let last;
    for (let i = 0; i < attempts; i++) {
      try {
        return await fn();
      } catch (e) {
        if (!(e instanceof TransientStorageFailure)) {
          throw e;
        }
        last = e;
        await new Promise((r) => setTimeout(r, 3000 * (i + 1)));
      }
    }
    throw last;
  }

  /**
   * @param {string} localPath
   * @param {string} key
   * @param {(progress: {completed_parts: number, total_parts: number}) => void} [onProgress]
   */
  async put(localPath, key, onProgress) {
    const size = (await stat(localPath)).size;
    const url = this.objectUrl(key);

    if (size < MULTIPART_FROM) {
      const response = await this.withRetry(() =>
        this.send("PUT", url, "UNSIGNED-PAYLOAD", { "Content-Length": String(size), "Content-Type": "application/octet-stream" }, { file: localPath }),
      );
      if (!response.ok) {
        throw new StorageRefusal(`Envoi vers le stockage objet refusé : ${describeRefusal(response)}`);
      }
      return { url, bucket: this.bucket, path: key, size, etag: (response.headers.etag ?? "").replace(/"/g, "") || null };
    }

    return this.multipart(localPath, key, size, url, onProgress);
  }

  async multipart(localPath, key, size, url, onProgress) {
    const init = await this.withRetry(() => this.send("POST", `${url}?uploads`, sha256(""), {}));
    if (!init.ok) {
      throw new StorageRefusal(`Initiation multipart refusée : ${describeRefusal(init)}`);
    }
    const uploadId = /<UploadId>(.+?)<\/UploadId>/s.exec(init.body.toString("utf8"))?.[1]?.trim();
    if (!uploadId) {
      throw new StorageRefusal("UploadId absent de la réponse d'initiation multipart.");
    }

    const totalParts = Math.ceil(size / PART_SIZE);
    const parts = [];
    const handle = await open(localPath, "r");
    try {
      for (let number = 1; number <= totalParts; number++) {
        const length = Math.min(PART_SIZE, size - (number - 1) * PART_SIZE);
        const chunk = Buffer.alloc(length);
        await handle.read(chunk, 0, length, (number - 1) * PART_SIZE);
        const partUrl = `${url}?partNumber=${number}&uploadId=${encodeURIComponent(uploadId)}`;
        const response = await this.withRetry(() => this.send("PUT", partUrl, sha256(chunk), { "Content-Length": String(length) }, { body: chunk }), 6);
        if (!response.ok) {
          await this.abort(url, uploadId);
          throw new StorageRefusal(`Tranche ${number} refusée : ${describeRefusal(response)}`);
        }
        parts.push({ number, etag: response.headers.etag ?? "" });
        onProgress?.({ completed_parts: number, total_parts: totalParts });
      }
    } catch (e) {
      if (e instanceof TransientStorageFailure) {
        await this.abort(url, uploadId);
      }
      throw e;
    } finally {
      await handle.close();
    }

    const xml =
      '<?xml version="1.0" encoding="UTF-8"?>\n<CompleteMultipartUpload>\n' +
      parts.map((p) => `  <Part>\n    <PartNumber>${p.number}</PartNumber>\n    <ETag>${escapeXml(p.etag.trim())}</ETag>\n  </Part>\n`).join("") +
      "</CompleteMultipartUpload>";
    const done = await this.withRetry(() =>
      this.send("POST", `${url}?uploadId=${encodeURIComponent(uploadId)}`, sha256(xml), { "Content-Type": "application/xml", "Content-Length": String(Buffer.byteLength(xml)) }, { body: xml }),
    );
    const text = done.body.toString("utf8");
    // Un 200 peut porter un <Error> : S3 envoie des blancs pendant qu'il termine, puis
    // écrit le vrai résultat dans le corps.
    if (!done.ok || text.includes("<Error>") || !text.includes("<CompleteMultipartUploadResult")) {
      await this.abort(url, uploadId);
      throw new StorageRefusal(`Finalisation multipart refusée : ${describeRefusal(done)}`);
    }
    return { url, bucket: this.bucket, path: key, size, etag: null };
  }

  async abort(url, uploadId) {
    try {
      await this.send("DELETE", `${url}?uploadId=${encodeURIComponent(uploadId)}`, sha256(""), {});
    } catch {
      // Au mieux : une partie orpheline coûte quelques octets, pas une sauvegarde.
    }
  }

  async get(key, localPath) {
    const url = this.objectUrl(key);
    const response = await this.withRetry(() => this.send("GET", url, sha256(""), {}, { sink: localPath }));
    if (!response.ok) {
      throw new StorageRefusal(`Téléchargement refusé : ${describeRefusal(response)}`);
    }
    return localPath;
  }

  /** Taille de l'objet, `null` s'il n'existe pas. */
  async size(key) {
    const response = await this.withRetry(() => this.send("HEAD", this.objectUrl(key), sha256(""), {}));
    if (response.status === 404) {
      return null;
    }
    if (!response.ok) {
      throw new StorageRefusal(`Vérification refusée : ${describeRefusal(response)}`);
    }
    return Number(response.headers["content-length"] ?? NaN);
  }

  /** `false` sur un refus, sans lever : la rétention garde alors la ligne. */
  async delete(key) {
    try {
      const response = await this.send("DELETE", this.objectUrl(key), sha256(""), {});
      return response.ok || response.status === 404;
    } catch {
      return false;
    }
  }
}

function escapeXml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}
