/**
 * La version de l'agent, telle qu'elle part sur le fil (`meta.plugin_version`,
 * `agent_version` du battement).
 *
 * Écrite ici et relue depuis `package.json` par un test : l'agent ne se met pas à jour
 * lui-même, donc savoir quelle version répond sur chaque site est la seule chose qui
 * transforme « on ne peut pas pousser un correctif » en « on peut dire qui doit le tirer ».
 */
export const AGENT_VERSION = "0.1.0";
