import { spawn } from "node:child_process";
import { createReadStream, createWriteStream, existsSync } from "node:fs";
import { copyFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

/**
 * La base du projet : PostgreSQL, MySQL/MariaDB, MongoDB ou SQLite, lue depuis
 * `DATABASE_URL` (la convention de Prisma et Drizzle), `MONGODB_URI` ou
 * `sentinelo.config.json`.
 *
 * ## Les outils du moteur, pas un pilote embarqué
 *
 * Comme l'agent Composer appelle `mysqldump`, on appelle `pg_dump`, `mysqldump`,
 * `mongodump`, `sqlite3`. Ce sont les seuls à savoir produire un dump fidèle de LEUR moteur
 * (types, séquences, index, encodages), et ils évitent à l'agent toute dépendance native.
 * `sentinelo-agent init` vérifie qu'ils sont là et nomme le paquet à installer sinon.
 *
 * ## Le mot de passe ne passe JAMAIS en argument
 *
 * La ligne de commande d'un processus est lisible par tous les utilisateurs de la machine
 * (`ps`). Il voyage donc par `PGPASSWORD`, `MYSQL_PWD`, ou un fichier de configuration
 * 0600 pour `mongodump`.
 */

export class DatabaseError extends Error {
  constructor(message) {
    super(message);
    this.name = "DatabaseError";
  }
}

/** Ce qu'il faut installer quand un outil manque — le message doit nommer le geste. */
const PACKAGES = {
  pg_dump: "postgresql-client (Debian/Ubuntu : apt install postgresql-client)",
  psql: "postgresql-client (Debian/Ubuntu : apt install postgresql-client)",
  mysqldump: "mysql-client ou mariadb-client (apt install default-mysql-client)",
  mysql: "mysql-client ou mariadb-client (apt install default-mysql-client)",
  mongodump: "MongoDB Database Tools (https://www.mongodb.com/try/download/database-tools)",
  mongorestore: "MongoDB Database Tools (https://www.mongodb.com/try/download/database-tools)",
  sqlite3: "sqlite3 (apt install sqlite3)",
};

/**
 * @param {string} command
 * @param {string[]} args
 * @param {{env?: Record<string,string>, stdinFile?: string, stdoutFile?: string}} [options]
 */
function run(command, args, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { env: { ...process.env, ...(options.env ?? {}) }, stdio: ["pipe", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d) => {
      stderr = (stderr + d.toString()).slice(-4000);
    });
    if (options.stdoutFile) {
      child.stdout.pipe(createWriteStream(options.stdoutFile));
    } else {
      child.stdout.resume();
    }
    if (options.stdinFile) {
      createReadStream(options.stdinFile).pipe(child.stdin);
    } else {
      child.stdin.end();
    }
    child.on("error", (e) => {
      reject(
        e.code === "ENOENT"
          ? new DatabaseError(`Outil « ${command} » introuvable sur ce serveur. À installer : ${PACKAGES[command] ?? command}.`)
          : new DatabaseError(`${command} : ${e.message}`),
      );
    });
    child.on("close", (code) => {
      if (code === 0) {
        resolvePromise(stderr);
      } else {
        reject(new DatabaseError(`${command} a échoué (code ${code}) : ${stderr.trim().split("\n").slice(-3).join(" ") || "aucun détail"}`));
      }
    });
  });
}

/** L'outil répond-il ? Pour `init` et le diagnostic. */
export async function toolAvailable(command) {
  try {
    await run(command, ["--version"]);
    return true;
  } catch (e) {
    return !String(e.message).includes("introuvable");
  }
}

/**
 * @param {string|null} url
 * @param {string} projectRoot
 * @returns {Database|null}
 */
export function databaseFromUrl(url, projectRoot) {
  if (!url) {
    return null;
  }
  const raw = String(url).trim();
  if (/^(file:|sqlite:)/i.test(raw) || /\.(sqlite3?|db)$/i.test(raw)) {
    return new SqliteDatabase(resolveSqlitePath(raw, projectRoot));
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new DatabaseError("URL de base de données illisible (DATABASE_URL). Format attendu : postgresql://, mysql://, mongodb:// ou file:./base.sqlite");
  }
  const protocol = parsed.protocol.replace(/:$/, "").toLowerCase();
  if (protocol === "postgres" || protocol === "postgresql") {
    return new PostgresDatabase(parsed);
  }
  if (protocol === "mysql" || protocol === "mariadb") {
    return new MysqlDatabase(parsed);
  }
  if (protocol === "mongodb" || protocol === "mongodb+srv") {
    return new MongoDatabase(raw, parsed);
  }
  throw new DatabaseError(`Moteur de base non pris en charge : ${protocol}. Pris en charge : PostgreSQL, MySQL/MariaDB, MongoDB, SQLite.`);
}

/**
 * Prisma résout `file:./dev.db` par rapport au dossier du SCHÉMA (`prisma/`), pas à la
 * racine : on essaie les deux, dans cet ordre, et on garde la racine si aucun n'existe.
 */
function resolveSqlitePath(raw, projectRoot) {
  const path = raw.replace(/^(file:|sqlite:)(\/\/)?/i, "").split("?")[0];
  if (isAbsolute(path)) {
    return path;
  }
  const fromPrisma = resolve(projectRoot, "prisma", path);
  return existsSync(fromPrisma) ? fromPrisma : resolve(projectRoot, path);
}

/** @typedef {PostgresDatabase|MysqlDatabase|MongoDatabase|SqliteDatabase} Database */

class PostgresDatabase {
  constructor(url) {
    this.engine = "postgresql";
    this.entry = "database.sql";
    this.url = url;
  }

  databaseName() {
    return decodeURIComponent(this.url.pathname.replace(/^\//, "")) || null;
  }

  env() {
    const env = { PGPASSWORD: decodeURIComponent(this.url.password) };
    const sslmode = this.url.searchParams.get("sslmode");
    if (sslmode) {
      env.PGSSLMODE = sslmode;
    }
    return env;
  }

  args() {
    const args = ["-h", this.url.hostname || "localhost", "-p", this.url.port || "5432"];
    if (this.url.username) {
      args.push("-U", decodeURIComponent(this.url.username));
    }
    return args;
  }

  async dump(destination) {
    // --clean --if-exists : le dump recrée ce qu'il décrit, donc une restauration ne
    // dépend pas de l'état de la base cible. --no-owner : le rôle du serveur restauré
    // n'est pas forcément celui d'origine.
    await run("pg_dump", [...this.args(), "--clean", "--if-exists", "--no-owner", "--no-privileges", "--format=plain", "-f", destination, this.databaseName()], { env: this.env() });
  }

  async restore(source) {
    // Une seule transaction, arrêt à la première erreur : un import à moitié joué est
    // pire qu'un refus, la base reste alors celle d'avant.
    await run("psql", [...this.args(), "--single-transaction", "-v", "ON_ERROR_STOP=1", "-q", "-f", source, this.databaseName()], { env: this.env() });
  }

  tools() {
    return ["pg_dump", "psql"];
  }
}

class MysqlDatabase {
  constructor(url) {
    this.engine = "mysql";
    this.entry = "database.sql";
    this.url = url;
  }

  databaseName() {
    return decodeURIComponent(this.url.pathname.replace(/^\//, "")) || null;
  }

  args() {
    const args = ["--host", this.url.hostname || "localhost", "--port", this.url.port || "3306", "--default-character-set=utf8mb4"];
    if (this.url.username) {
      args.push("--user", decodeURIComponent(this.url.username));
    }
    return args;
  }

  async dump(destination) {
    await run(
      "mysqldump",
      [...this.args(), "--add-drop-table", "--single-transaction", "--quick", "--no-tablespaces",`--result-file=${destination}`, this.databaseName()],
      { env: { MYSQL_PWD: decodeURIComponent(this.url.password) } },
    );
  }

  async restore(source) {
    await run("mysql", [...this.args(), this.databaseName()], { env: { MYSQL_PWD: decodeURIComponent(this.url.password) }, stdinFile: source });
  }

  tools() {
    return ["mysqldump", "mysql"];
  }
}

class MongoDatabase {
  constructor(raw, url) {
    this.engine = "mongodb";
    this.entry = "database.archive";
    this.raw = raw;
    this.url = url;
  }

  databaseName() {
    return decodeURIComponent(this.url.pathname.replace(/^\//, "")) || null;
  }

  /** L'URI complète dans un fichier 0600 — `--uri` la mettrait dans `ps`. */
  async withConfig(workDir, fn) {
    const config = join(workDir, `mongo-${process.pid}-${Date.now()}.yaml`);
    await writeFile(config, `uri: ${JSON.stringify(this.raw)}\n`, { mode: 0o600 });
    try {
      return await fn(config);
    } finally {
      await rm(config, { force: true });
    }
  }

  async dump(destination, workDir) {
    await this.withConfig(workDir, (config) => run("mongodump", [`--config=${config}`, `--archive=${destination}`, "--gzip"]));
  }

  async restore(source, workDir) {
    // --drop : chaque collection est remplacée, pas fusionnée — une restauration rend
    // l'état sauvegardé, pas un mélange des deux.
    await this.withConfig(workDir, (config) => run("mongorestore", [`--config=${config}`, `--archive=${source}`, "--gzip", "--drop"]));
  }

  tools() {
    return ["mongodump", "mongorestore"];
  }
}

class SqliteDatabase {
  constructor(path) {
    this.engine = "sqlite";
    this.entry = "database.sqlite";
    this.path = path;
  }

  databaseName() {
    return this.path;
  }

  async dump(destination) {
    if (!existsSync(this.path)) {
      throw new DatabaseError(`Base SQLite introuvable : ${this.path}`);
    }
    try {
      // `.backup` : une copie cohérente même si l'application écrit pendant ce temps.
      await run("sqlite3", [this.path, `.backup '${destination.replace(/'/g, "''")}'`]);
    } catch (e) {
      if (!String(e.message).includes("introuvable")) {
        throw e;
      }
      // Sans l'outil, une copie brute — cohérente seulement si personne n'écrit. Le
      // journal le dit, plutôt que de laisser croire à une copie transactionnelle.
      await copyFile(this.path, destination);
      this.lastWarning = "sqlite3 absent : copie brute du fichier, cohérente seulement si l'application n'écrivait pas à cet instant.";
    }
  }

  async restore(source) {
    const tmp = `${this.path}.sentinelo-restore`;
    await copyFile(source, tmp);
    // Les journaux WAL de l'ancienne base décriraient des pages qui n'existent plus.
    await rm(`${this.path}-wal`, { force: true });
    await rm(`${this.path}-shm`, { force: true });
    await rename(tmp, this.path);
  }

  tools() {
    return ["sqlite3"];
  }
}

export async function fileSize(path) {
  try {
    return (await stat(path)).size;
  } catch {
    return 0;
  }
}
