import { createHmac } from "node:crypto";

import { Collection } from "./state/collection.js";
import { request } from "./support/http.js";
import { store, parse } from "./support/timestamps.js";

/**
 * Webhooks vers la plateforme — jumeaux de `WebhookDispatcher` et de la file de
 * `QueueingWebhookEmitter`.
 *
 * Corps PLAT : le payload, puis `event`, `site_uuid` et `timestamp` (secondes Unix) qui
 * l'emportent sur toute clé homonyme. Signature `sha256=<hmac hex>` calculée sur les
 * OCTETS EXACTS envoyés, sous `X-Sentinelo-Signature` et, pour les anciens backends,
 * `X-WNT-Signature`. Le backend refuse un horodatage à plus de 300 s : une livraison
 * retentée est donc RE-SIGNÉE avec une date fraîche, jamais rejouée telle quelle.
 *
 * Un échec ne perd rien : la livraison part en file, retentée après 0, 5, 30, 120 puis
 * 720 minutes, abandonnée ensuite. Le webhook n'est qu'un raccourci — la plateforme sonde
 * de toute façon les routes de statut —, mais un raccourci perdu coûte des minutes
 * d'affichage faux.
 */

const BACKOFF_MINUTES = [0, 5, 30, 120, 720];
const MAX_ATTEMPTS = 5;

const ROUTES = { security: "security", backup: "backup", restore: "restore", update: "update", login: "login-alert", alert: "alert", seo: "audit" };

export function routeFor(event) {
  const prefix = String(event).split(".")[0];
  return ROUTES[prefix] ?? prefix;
}

export function sign(body, secret) {
  return createHmac("sha256", secret).update(body).digest("hex");
}

export class Webhooks {
  /** @param {import("./agent.js").Agent} agent */
  constructor(agent) {
    this.agent = agent;
    this.queue = new Collection(agent.settings.dataDir, "webhook-queue");
  }

  /** Envoie, et met en file sur échec. Ne lève jamais : notifier n'emporte pas le travail notifié. */
  async send(event, payload) {
    try {
      const outcome = await this.deliver(event, payload);
      if (outcome === "skipped" || outcome === "sent") {
        return outcome === "sent";
      }
      this.queue.insert({ event_type: event, payload_json: JSON.stringify(payload), attempts: 1, max_attempts: MAX_ATTEMPTS, next_attempt_at: store(new Date(Date.now() + BACKOFF_MINUTES[1] * 60_000)), last_error: outcome, created_at: store(), status: "pending" });
      return false;
    } catch (e) {
      this.agent.logger.warning("webhook", `${event} : ${e.message}`);
      return false;
    }
  }

  /** @returns {Promise<"sent"|"skipped"|string>} `skipped` = pas encore enrôlé ; une chaîne = la raison de l'échec */
  async deliver(event, payload) {
    const { config } = this.agent;
    const saasUrl = this.agent.saasUrl();
    const siteUuid = config.get("site_uuid");
    const secret = config.get("webhook_secret");
    if (!saasUrl || !siteUuid || !secret) {
      return "skipped";
    }
    const timestamp = Math.floor(Date.now() / 1000);
    const body = JSON.stringify({ ...payload, event, site_uuid: siteUuid, timestamp });
    const signature = `sha256=${sign(body, secret)}`;
    const response = await request("POST", `${saasUrl.replace(/\/+$/, "")}/api/webhooks/${routeFor(event)}`, {
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(Buffer.byteLength(body)),
        "X-Sentinelo-Site-UUID": siteUuid,
        "X-Sentinelo-Event": event,
        "X-Sentinelo-Timestamp": String(timestamp),
        "X-Sentinelo-Signature": signature,
        "X-WNT-Signature": signature,
      },
      body,
      timeout: 10,
    });
    if (response.ok) {
      return "sent";
    }
    const reason = response.status === 0 ? `transport : ${response.error}` : `HTTP ${response.status}`;
    this.agent.logger.warning("webhook", `${event} non livré (${reason})`);
    return reason;
  }

  /** Vide la file : au plus 50 livraisons dues par passage. */
  async drain() {
    const now = Date.now();
    const due = this.queue
      .filter((r) => r.status === "pending" && (parse(r.next_attempt_at)?.getTime() ?? 0) <= now)
      .slice(0, 50);
    for (const item of due) {
      let payload;
      try {
        payload = JSON.parse(item.payload_json);
      } catch {
        this.queue.update(item.id, { status: "invalid", last_error: "payload illisible" });
        continue;
      }
      const outcome = await this.deliver(item.event_type, payload);
      if (outcome === "sent") {
        this.queue.remove(item.id);
      } else if (outcome !== "skipped") {
        const attempts = item.attempts + 1;
        if (attempts >= item.max_attempts) {
          this.queue.update(item.id, { status: "abandoned", attempts, last_error: outcome, abandoned_at: store() });
        } else {
          this.queue.update(item.id, { attempts, last_error: outcome, next_attempt_at: store(new Date(now + BACKOFF_MINUTES[attempts] * 60_000)) });
        }
      }
    }
    // Les abandons de plus de 30 jours ne servent plus à personne.
    this.queue.removeWhere((r) => r.status !== "pending" && now - (parse(r.abandoned_at ?? r.created_at)?.getTime() ?? now) > 30 * 86_400_000);
  }

  purgeable() {
    return this.queue.all().length;
  }
}
