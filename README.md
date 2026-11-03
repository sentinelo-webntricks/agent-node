# @sentinelo/agent

L'agent Sentinelo pour les applications **Node.js** hébergées sur votre serveur :
**Next.js, Nuxt, Remix, SvelteKit, Astro, NestJS, Express, Fastify…**

Il parle exactement le même protocole que les agents WordPress, PrestaShop et Composer :
la plateforme le supervise sans savoir dans quel langage il est écrit.

## Ce que fait l'agent

| | |
|---|---|
| **Sauvegarde** | base (PostgreSQL, MySQL/MariaDB, MongoDB, SQLite) + code + fichiers publics + envois, **chiffrés avant de quitter le serveur**, envoyés vers le stockage objet, rétention GFS |
| **Restauration** | sauvegarde de sécurité préalable, empreinte SHA-256 vérifiée **avant** d'écrire quoi que ce soit, maintenance posée pendant l'opération |
| **Scan de sécurité** | 9 contrôles notés + l'inventaire des paquets (verrou npm, pnpm ou yarn) pour la corrélation CVE côté plateforme |
| **Supervision** | battement toutes les 5 minutes, version de l'application et de Node.js, journaux consultables depuis la plateforme |

## Ce qu'il ne fait pas, et pourquoi

**Il n'applique aucune mise à jour de paquets.** `npm update` + reconstruction + redémarrage
n'est pas atomique, et écrire dans `node_modules` ferait diverger le code exécuté de celui
que votre pipeline a construit. Les mises à jour se signalent ; elles s'appliquent par votre
déploiement.

**Il ne se met pas à jour lui-même.** Mettez-le à jour avec `npm install -g @sentinelo/agent`.
La plateforme connaît la version qui répond sur chaque site et vous dit quand en changer.

**Il ne tourne pas sur Vercel, Netlify ou une plateforme « serverless ».** Il faut un disque
et un processus qui dure. Un site statique ou serverless reste supervisé sans agent
(disponibilité, performance, SEO, scan externe).

## Installation

Sur le serveur du site, avec l'utilisateur qui fait tourner l'application. Les étapes 3 et
4 se font **à la main** : aucune commande ne les fait à votre place.

### 1. Installer l'agent

Node.js 20 ou plus récent.

```bash
npm install -g @sentinelo/agent
```

### 2. Le préparer à la racine du projet

```bash
cd /chemin/du/projet
sentinelo-agent init
```

`init` crée le répertoire de données `.sentinelo/` (à ajouter à votre `.gitignore`), génère
le **secret de chiffrement** dans `.sentinelo/agent.env`, et vérifie que l'outil de dump de
votre base est installé :

| Base | Outils nécessaires | Debian / Ubuntu |
|---|---|---|
| PostgreSQL | `pg_dump`, `psql` | `apt install postgresql-client` |
| MySQL / MariaDB | `mysqldump`, `mysql` | `apt install default-mysql-client` |
| MongoDB | `mongodump`, `mongorestore` | [MongoDB Database Tools](https://www.mongodb.com/try/download/database-tools) |
| SQLite | `sqlite3` (recommandé) | `apt install sqlite3` |

La base est lue dans `DATABASE_URL` (la convention de Prisma et Drizzle), ou `MONGODB_URI`,
depuis l'environnement ou les fichiers `.env` du projet. Sans base configurée, seuls les
fichiers sont sauvegardés.

> **Gardez une copie du secret hors du serveur.** Il déchiffre les sauvegardes : si le
> serveur est perdu, il faut ce secret pour les relire. `init` l'affiche une seule fois.

### 3. Brancher le proxy inverse — à la main

L'agent écoute par défaut sur `127.0.0.1:8787`. **Le port 8787 n'a rien d'obligatoire** :
s'il est déjà pris sur le serveur, prenez n'importe quel port libre, avec
`SENTINELO_PORT=<port>` dans l'environnement du démon ou `"port": <port>` dans
`sentinelo.config.json`, et reportez ce même port dans le proxy ci-dessous.

Votre proxy inverse doit transmettre `/_sentinelo/v1/` à l'agent, et rendre la page de
maintenance quand l'agent la pose :

**nginx**

```nginx
location /_sentinelo/v1/ {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header X-Forwarded-For $remote_addr;
}

# Maintenance posée par l'agent pendant une restauration.
if (-f /chemin/du/projet/.sentinelo/maintenance.flag) {
    return 503;
}
```

**Caddy**

```caddy
handle /_sentinelo/v1/* {
    reverse_proxy 127.0.0.1:8787
}
```

**Traefik** : une règle `PathPrefix(`/_sentinelo/v1/`)` vers le service de l'agent, avec une
priorité supérieure à celle de l'application.

### 4. Lancer le démon — à la main

Il doit redémarrer avec le serveur. Au choix :

**PM2**

```bash
pm2 start sentinelo-agent --name sentinelo -- serve --project /chemin/du/projet
pm2 save
```

**systemd** (`/etc/systemd/system/sentinelo-agent.service`)

```ini
[Unit]
Description=Agent Sentinelo
After=network.target

[Service]
User=www-data
WorkingDirectory=/chemin/du/projet
ExecStart=/usr/bin/env sentinelo-agent serve
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now sentinelo-agent
```

**Docker** : un conteneur `node:22` qui monte le projet et lance `sentinelo-agent serve`,
sur le même réseau que le proxy.

### 5. Enrôler le site

Créez le site sur la plateforme (type **Node.js**), copiez la clé affichée, puis :

```bash
sentinelo-agent enroll <clé>
```

Sur un déploiement automatisé, posez plutôt `SENTINELO_API_KEY=<clé>` dans l'environnement
du démon : il l'adopte au démarrage.

### Vérifier

```bash
curl -s https://votre-site/_sentinelo/v1/health
sentinelo-agent status
```

Avant l'enrôlement, `health` répond `403 NOT_CONFIGURED` dans une enveloppe JSON : l'agent
est bien joint. Un 404 HTML veut dire que l'étape 3 manque ; un 502, que l'étape 4 manque.

## Ce qui est sauvegardé

| | |
|---|---|
| Base | dump du moteur (`pg_dump`, `mysqldump`, `mongodump --archive`, `sqlite3 .backup`) |
| Code | la racine du projet, **sans** `node_modules`, `.next`, `.nuxt`, `dist`, `build`, `.git`, `coverage`… |
| Fichiers publics | `public/` |
| Envois | `public/uploads`, `uploads` ou `storage` (le premier qui existe) |

Les fichiers `.env*` ne sont **jamais** sauvegardés : ils portent vos secrets, qui ont leur
place dans votre gestionnaire de secrets, pas dans un seau. Une restauration ne touche ni
`node_modules`, ni `.next`, ni `.env*`, ni l'état de l'agent — elle ne déconnecte donc
jamais le site.

Pour ajuster, `sentinelo.config.json` à la racine du projet :

```json
{
  "siteUrl": "https://www.exemple.fr",
  "port": 8787,
  "paths": { "uploads": "data/uploads" },
  "excludePaths": ["*.mp4", "public/videos"]
}
```

## Déchiffrer une archive à la main

```bash
SENTINELO_SECRET=<votre secret> sentinelo-agent decrypt backup-….tar.enc backup.tar
tar -xf backup.tar
```

## Commandes

```
sentinelo-agent init                   prépare le répertoire de données et le secret
sentinelo-agent enroll <clé>           rattache le site à la plateforme
sentinelo-agent serve                  lance le démon
sentinelo-agent status                 ce que l'agent sait de lui-même
sentinelo-agent run <tâche>            heartbeat | backup | scan | webhooks | cleanup
sentinelo-agent decrypt <src> <dst>    déchiffre une archive de sauvegarde
```

Options : `--project <dossier>` (défaut : le dossier courant), `--config <fichier>`.
