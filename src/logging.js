import { appendFileSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { scrub } from "./support/redactor.js";
import { local, localDay } from "./support/timestamps.js";

/**
 * Journaux de l'agent : `[AAAA-MM-JJ HH:MM:SS] [NIVEAU] [canal] message`, un fichier par
 * jour (`sentinelo-AAAA-MM-JJ.log`) — la forme que `LogReader` analyse côté PHP, donc la
 * seule qui laisse l'interface filtrer par niveau et par canal.
 */

const FILE_PREFIX = "sentinelo-";
export const DEFAULT_LINES = 200;
export const MAX_LINES = 1000;
const LEVELS = { debug: 0, info: 1, warning: 2, error: 3 };

export class Logger {
  /** @param {string} directory @param {{echo?: boolean}} [options] */
  constructor(directory, options = {}) {
    this.directory = directory;
    this.echo = options.echo ?? false;
    this.unwritable = false;
  }

  /** @param {"debug"|"info"|"warning"|"error"} level @param {string} channel @param {string} message */
  log(level, channel, message) {
    const now = new Date();
    const line = `[${local(now)}] [${level.toUpperCase()}] [${channel}] ${String(message).replace(/\r?\n/g, " ")}\n`;
    if (this.echo) {
      process.stderr.write(line);
    }
    if (this.unwritable) {
      return;
    }
    try {
      mkdirSync(this.directory, { recursive: true, mode: 0o700 });
      appendFileSync(join(this.directory, `${FILE_PREFIX}${localDay(now)}.log`), line, { mode: 0o600 });
    } catch {
      // Un disque en lecture seule ne doit jamais faire échouer ce que l'on journalise.
      this.unwritable = true;
    }
  }

  info(channel, message) { this.log("info", channel, message); }
  warning(channel, message) { this.log("warning", channel, message); }
  error(channel, message) { this.log("error", channel, message); }
}

export class LogReader {
  /** @param {string} directory */
  constructor(directory) {
    this.directory = directory;
  }

  timezone() {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  }

  availableDates() {
    let names;
    try {
      names = readdirSync(this.directory);
    } catch {
      return [];
    }
    return names
      .map((n) => /^sentinelo-(\d{4}-\d{2}-\d{2})\.log$/.exec(n)?.[1])
      .filter(Boolean)
      .sort()
      .reverse();
  }

  /**
   * @param {{date?: string|null, lines?: number, minLevel?: string|null, channel?: string|null}} options
   */
  tail({ date = null, lines = DEFAULT_LINES, minLevel = null, channel = null } = {}) {
    const available = this.availableDates();
    const resolved = this.resolveDate(date, available);
    const limit = Math.max(1, Math.min(Number(lines) || DEFAULT_LINES, MAX_LINES));

    if (resolved === null) {
      return { date: null, entries: [], returned: 0, truncated: false, available_dates: available };
    }

    let raw = [];
    try {
      raw = readFileSync(join(this.directory, `${FILE_PREFIX}${resolved}.log`), "utf8").split(/\r?\n/).filter((l) => l !== "");
    } catch {
      raw = [];
    }

    const entries = raw
      .map((line) => this.parse(line))
      .filter((e) => this.passesLevel(e.level, minLevel))
      .filter((e) => !channel || e.channel === channel);

    const total = entries.length;
    // La QUEUE, pas la tête : un incident se lit par la fin.
    const kept = total > limit ? entries.slice(-limit) : entries;

    return { date: resolved, entries: kept, returned: kept.length, truncated: total > limit, available_dates: available };
  }

  resolveDate(date, available) {
    if (date === null || date === undefined || String(date).trim() === "") {
      return available[0] ?? null;
    }
    // Seule une DATE passe : aucun `../` ne peut atteindre le nom de fichier.
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return null;
    }
    return available.includes(date) ? date : null;
  }

  parse(line) {
    const m = /^\[([^\]]+)\] \[([A-Z]+)\] \[([^\]]+)\] (.*)$/s.exec(line);
    if (!m) {
      return { at: null, level: "info", channel: "raw", message: scrub(line) };
    }
    const at = new Date(m[1].replace(" ", "T"));
    return {
      at: Number.isNaN(at.getTime()) ? null : at.toISOString().replace(/\.\d{3}Z$/, "+00:00"),
      at_local: m[1],
      level: m[2].toLowerCase(),
      channel: m[3],
      message: scrub(m[4]),
    };
  }

  passesLevel(level, minLevel) {
    if (!minLevel) {
      return true;
    }
    const floor = LEVELS[String(minLevel).toLowerCase()];
    if (floor === undefined) {
      return true;
    }
    return (LEVELS[level] ?? 1) >= floor;
  }
}
