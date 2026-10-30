import { readdirSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";

import { cleanExpired } from "./backup/retention.js";
import { adopt, heartbeat } from "./enrolment.js";

/**
 * Le planificateur — dans le démon, pas dans un cron système.
 *
 * Mêmes cadences que `TaskCatalogue` : battement et file de webhooks toutes les 5 min,
 * ménage quotidien, scan complet le lundi à 05:00. Les sauvegardes quotidiennes ne sont
 * PAS planifiées ici : la plateforme décide de la cadence (`BackupScheduler`) et appelle
 * `backup/run` — deux planificateurs pour un même travail, c'est deux fois le travail et
 * aucune autorité.
 *
 * Une tâche qui lève n'arrête jamais les autres, ni le démon.
 */

const MINUTE = 60_000;

export class Scheduler {
  /** @param {import("./agent.js").Agent} agent */
  constructor(agent) {
    this.agent = agent;
    this.timers = [];
    this.running = new Set();
  }

  start() {
    this.every("adopt", MINUTE, () => adopt(this.agent), 2_000);
    this.every("heartbeat", 5 * MINUTE, () => heartbeat(this.agent), 5_000);
    this.every("webhooks", 5 * MINUTE, () => this.agent.webhooks.drain(), 30_000);
    this.every("cleanup", 24 * 60 * MINUTE, () => this.cleanup(), 10 * MINUTE);
    this.every("weekly-scan", 15 * MINUTE, () => this.weeklyScan(), MINUTE);
  }

  stop() {
    for (const t of this.timers) {
      clearTimeout(t);
      clearInterval(t);
    }
    this.timers = [];
  }

  every(name, interval, task, firstDelay) {
    const run = async () => {
      if (this.running.has(name)) {
        return;
      }
      this.running.add(name);
      try {
        await task();
      } catch (e) {
        this.agent.logger.warning("scheduler", `Tâche ${name} en erreur : ${e?.message ?? e}`);
      } finally {
        this.running.delete(name);
      }
    };
    this.timers.push(setTimeout(run, firstDelay));
    const handle = setInterval(run, interval);
    handle.unref?.();
    this.timers.push(handle);
  }

  /** Lundi, après 05:00 heure locale, une fois par semaine — même après un redémarrage. */
  async weeklyScan(now = new Date()) {
    if (now.getDay() !== 1 || now.getHours() < 5 || !this.agent.config.get("api_key")) {
      return;
    }
    const week = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
    if (this.agent.config.get("last_weekly_scan") === week) {
      return;
    }
    this.agent.config.set("last_weekly_scan", week);
    await this.agent.scanRunner.start("full").done;
  }

  async cleanup() {
    const { agent } = this;
    await cleanExpired(agent.backups, async () => {
      try {
        return agent.storage();
      } catch {
        return null;
      }
    }, agent.logger);
    await agent.backupRunner.sweepOrphans();
    // Journaux de plus de 30 jours.
    const logs = join(agent.settings.dataDir, "logs");
    const limit = Date.now() - 30 * 24 * 60 * MINUTE;
    for (const name of (() => {
      try {
        return readdirSync(logs);
      } catch {
        return [];
      }
    })()) {
      const path = join(logs, name);
      try {
        if (statSync(path).mtimeMs < limit) {
          rmSync(path, { force: true });
        }
      } catch {
        // Fichier disparu entre-temps.
      }
    }
  }
}
