import { createReadStream, createWriteStream } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { pipeline } from "node:stream/promises";

/**
 * Le client HTTP sortant de l'agent — plateforme, stockage objet, sondes du scan.
 *
 * Pourquoi pas `fetch` : la signature SigV4 couvre l'en-tête `Host`, que `fetch` interdit
 * de fixer ; et un envoi de fichier ou un téléchargement vers le disque doivent passer en
 * flux, sans charger 500 Mo en mémoire. `node:http` fait les deux, sans dépendance.
 *
 * Un échec de transport ne lève pas : il rend `status: 0` et `error`, comme
 * `HttpResponse` côté PHP — l'appelant décide si c'est une panne ou une réponse.
 */

/**
 * @param {string} method
 * @param {string} url
 * @param {{headers?: Record<string, string>, body?: string|Buffer, file?: string, sink?: string, timeout?: number, maxBodyBytes?: number}} [options]
 * @returns {Promise<{status: number, headers: Record<string, string>, body: Buffer, error: string|null, ok: boolean}>}
 */
export function request(method, url, options = {}) {
  const target = new URL(url);
  const send = target.protocol === "https:" ? httpsRequest : httpRequest;
  const timeout = (options.timeout ?? 30) * 1000;
  const maxBody = options.maxBodyBytes ?? 8 * 1024 * 1024;

  return new Promise((resolvePromise) => {
    let settled = false;
    const finish = (value) => {
      if (!settled) {
        settled = true;
        resolvePromise({ ...value, ok: value.status >= 200 && value.status < 300 });
      }
    };

    const req = send(
      target,
      { method, headers: options.headers ?? {}, timeout },
      (res) => {
        const headers = Object.fromEntries(Object.entries(res.headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(",") : String(v ?? "")]));
        const status = res.statusCode ?? 0;

        if (options.sink && status >= 200 && status < 300) {
          pipeline(res, createWriteStream(options.sink))
            .then(() => finish({ status, headers, body: Buffer.alloc(0), error: null }))
            .catch((e) => finish({ status: 0, headers, body: Buffer.alloc(0), error: `écriture interrompue : ${e.message}` }));
          return;
        }

        const chunks = [];
        let size = 0;
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size <= maxBody) {
            chunks.push(chunk);
          }
        });
        res.on("end", () => finish({ status, headers, body: Buffer.concat(chunks), error: null }));
        res.on("error", (e) => finish({ status: 0, headers, body: Buffer.concat(chunks), error: e.message }));
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error(`délai dépassé (${timeout / 1000} s)`));
    });
    req.on("error", (e) => finish({ status: 0, headers: {}, body: Buffer.alloc(0), error: e.message }));

    if (options.file) {
      pipeline(createReadStream(options.file), req).catch((e) => finish({ status: 0, headers: {}, body: Buffer.alloc(0), error: e.message }));
    } else {
      req.end(options.body ?? undefined);
    }
  });
}

/** Le corps en texte, tronqué — pour un message d'erreur lisible, jamais un mur de HTML. */
export function excerpt(response, max = 300) {
  const text = response.body.toString("utf8").replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
