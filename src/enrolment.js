import { request, excerpt } from "./support/http.js";
import { AGENT_VERSION } from "./version.js";

/**
 * L'enrôlement : la poignée de main qui donne sa clé au site — jumelle de
 * `Enrolment\Enroller` (agent Composer).
 *
 * ## L'ordre, et pourquoi
 *
 * La clé est écrite AVANT l'appel de vérification : en répondant, la plateforme rappelle
 * l'agent sur `cloud-config` avec cette même clé pour lui pousser le stockage. En
 * contrepartie, tout échec RESTAURE la clé et l'adresse précédentes — se tromper de clé au
 * clavier ne doit pas déconnecter un site qui marchait.
 *
 * ## Pas de route HTTP d'enrôlement
 *
 * Elle devrait échapper à l'authentification : n'importe qui pourrait alors rattacher
 * l'agent d'un client à SA plateforme et lire ses sauvegardes. On enrôle depuis le
 * terminal du serveur, ou par `SENTINELO_API_KEY` au démarrage.
 */

export class EnrolmentError extends Error {}

/**
 * @param {import("./agent.js").Agent} agent
 * @param {string} apiKey
 * @param {string|null} [saasUrlOverride]
 */
export async function enrol(agent, apiKey, saasUrlOverride = null) {
  const key = String(apiKey ?? "").trim();
  if (key === "") {
    throw new EnrolmentError("Clé API vide : copiez-la depuis la fiche du site sur la plateforme.");
  }
  const { config } = agent;
  const saasUrl = (saasUrlOverride || agent.saasUrl()).replace(/\/+$/, "");
  const previous = { api_key: config.get("api_key"), saas_url: config.get("saas_url") };

  config.set("enrolment_attempted_at", Math.floor(Date.now() / 1000));
  config.set("saas_url", saasUrl);
  config.set("api_key", key);

  const app = agent.application();
  const body = JSON.stringify({
    site_url: agent.settings.siteUrl || config.get("site_url") || "",
    application: app.slug,
    application_version: app.version,
    php_version: null,
    runtime: "node",
    node_version: process.versions.node,
    agent_version: AGENT_VERSION,
  });

  let failure = null;
  let data = null;
  const response = await request("POST", `${saasUrl}/api/sites/verify`, {
    headers: { "Content-Type": "application/json", "Content-Length": String(Buffer.byteLength(body)), "X-Sentinelo-API-Key": key },
    body,
    timeout: 30,
  });
  if (response.status === 0) {
    failure = `Plateforme injoignable (${saasUrl}) : ${response.error}`;
  } else if (!response.ok) {
    failure = response.status === 401 || response.status === 404
      ? `Clé refusée par la plateforme (HTTP ${response.status}) : vérifiez qu'elle correspond bien à ce site.`
      : `La plateforme a répondu HTTP ${response.status} : ${excerpt(response)}`;
  } else {
    try {
      const decoded = JSON.parse(response.body.toString("utf8"));
      data = decoded?.data ?? decoded;
    } catch {
      failure = "Réponse de la plateforme illisible.";
    }
    if (!failure && !data?.site_uuid) {
      failure = "La plateforme n'a pas renvoyé d'identifiant de site (site_uuid).";
    }
  }

  if (failure) {
    config.set("api_key", previous.api_key);
    config.set("saas_url", previous.saas_url);
    agent.logger.error("enrolment", failure);
    throw new EnrolmentError(failure);
  }

  config.set("site_uuid", String(data.site_uuid));
  if (data.webhook_secret) {
    config.set("webhook_secret", String(data.webhook_secret));
  } else {
    agent.logger.warning("enrolment", "Aucun secret de webhook reçu : les notifications seront refusées par la plateforme.");
  }
  if (data.site_url && !agent.settings.siteUrl) {
    config.set("site_url", String(data.site_url));
  }
  config.set("connected_at", new Date().toISOString());
  agent.logger.info("enrolment", `Site enrôlé : ${data.site_uuid} (${saasUrl})`);
  return { siteUuid: String(data.site_uuid), saasUrl };
}

/**
 * Adoption automatique de `SENTINELO_API_KEY` : au plus une tentative toutes les 5 min,
 * et jamais d'exception — c'est le chemin d'un déploiement où personne n'ouvre de terminal.
 *
 * @param {import("./agent.js").Agent} agent
 */
export async function adopt(agent) {
  const key = String(agent.settings.env.SENTINELO_API_KEY ?? "").trim();
  if (key === "" || agent.config.get("api_key") === key) {
    return false;
  }
  const last = Number(agent.config.get("enrolment_attempted_at") ?? 0);
  if (Date.now() / 1000 - last < 300) {
    return false;
  }
  try {
    await enrol(agent, key);
    return true;
  } catch {
    return false;
  }
}

/** @param {import("./agent.js").Agent} agent */
export async function heartbeat(agent) {
  const { config } = agent;
  const saasUrl = agent.saasUrl();
  const siteUuid = config.get("site_uuid");
  const key = config.get("api_key");
  if (!saasUrl || !siteUuid || !key) {
    return false;
  }
  const app = agent.application();
  const body = JSON.stringify({
    site_uuid: siteUuid,
    timestamp: Math.floor(Date.now() / 1000),
    application: app.slug,
    application_version: app.version,
    php_version: null,
    runtime: "node",
    node_version: process.versions.node,
    agent_version: AGENT_VERSION,
  });
  const response = await request("POST", `${saasUrl.replace(/\/+$/, "")}/api/sites/${siteUuid}/heartbeat`, {
    headers: { "Content-Type": "application/json", "Content-Length": String(Buffer.byteLength(body)), "X-Sentinelo-API-Key": key, "X-Sentinelo-Site-UUID": siteUuid },
    body,
    timeout: 10,
  });
  if (response.ok) {
    config.set("last_heartbeat", Math.floor(Date.now() / 1000));
    return true;
  }
  agent.logger.warning("heartbeat", `Battement refusé : ${response.status === 0 ? response.error : `HTTP ${response.status}`}`);
  return false;
}
