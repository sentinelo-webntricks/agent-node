import { createServer } from "node:http";

/**
 * Le serveur HTTP de l'agent : un unique point d'entrée `/_sentinelo/v1/<route>`, GET et
 * POST confondus — comme la route attrape-tout du bundle Symfony.
 *
 * L'agent écoute par défaut sur `127.0.0.1` : il est joint par le proxy inverse du site,
 * qui lui transmet `/_sentinelo/v1/*`. L'adresse du client se lit donc dans
 * `X-Forwarded-For` / `X-Real-IP` QUAND la connexion vient de la boucle locale — et
 * seulement alors, sinon n'importe qui choisirait l'IP sous laquelle il est compté.
 */

export const BASE_PATH = "/_sentinelo/v1/";
const MAX_BODY_BYTES = 1024 * 1024;

const NO_CACHE = {
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0, private",
  Pragma: "no-cache",
  Expires: "0",
};

/**
 * @param {(request: {route: string, method: string, ip: string, headers: Record<string, string>, query: URLSearchParams, body: any}) => Promise<{status: number, body: any}>} handle
 */
export function createAgentServer(handle) {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://agent.local");

    if (!url.pathname.startsWith(BASE_PATH)) {
      send(res, 404, { success: false, error: { code: "NOT_FOUND", message: "Hors du périmètre de l'agent.", http_status: 404 } });
      return;
    }

    let body = {};
    try {
      const raw = await readBody(req);
      if (raw.length > 0) {
        body = JSON.parse(raw.toString("utf8"));
      }
    } catch (e) {
      send(res, 400, { success: false, error: { code: "VALIDATION_ERROR", message: `Corps illisible : ${e.message}`, http_status: 400 } });
      return;
    }

    const headers = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(",") : v ?? ""]));

    const response = await handle({
      route: decodeURIComponent(url.pathname.slice(BASE_PATH.length)).replace(/^\/+|\/+$/g, ""),
      method: req.method ?? "GET",
      ip: clientIp(req, headers),
      headers,
      query: url.searchParams,
      body: body && typeof body === "object" ? body : {},
    });

    send(res, response.status, response.body);
  });
}

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(payload), ...NO_CACHE });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolvePromise, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("corps de requête trop volumineux"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolvePromise(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function clientIp(req, headers) {
  const peer = (req.socket.remoteAddress ?? "").replace(/^::ffff:/, "");
  const loopback = peer === "127.0.0.1" || peer === "::1";
  if (loopback) {
    const forwarded = headers["x-forwarded-for"]?.split(",")[0]?.trim() || headers["x-real-ip"]?.trim();
    if (forwarded) {
      return forwarded;
    }
  }
  return peer;
}
