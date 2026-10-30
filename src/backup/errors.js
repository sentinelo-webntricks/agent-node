/** Une sauvegarde tourne déjà : refus en 409, jamais en 500 — rien n'est cassé. */
export class BackupAlreadyRunning extends Error {
  constructor(id) {
    super(`Une sauvegarde est déjà en cours (ID: ${id}). Attendez qu'elle se termine, puis relancez.`);
    this.name = "BackupAlreadyRunning";
  }
}

/** Un différentiel demandé sans sa base : refus en 400, le remède est côté plateforme. */
export class BaseBackupRequired extends Error {
  constructor(message) {
    super(message);
    this.name = "BaseBackupRequired";
  }
}
