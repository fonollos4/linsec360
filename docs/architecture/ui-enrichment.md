# Enrichissement de l’interface LinSec360

Ce document décrit le flux UI ajouté autour de l’inventaire, du terminal,
d’OpenSCAP et du patching natif. Il conserve volontairement la charte, les
composants et les conventions existants (`App.tsx`, `api.ts`, `index.css`).

## 1. Principe directeur

L’administrateur crée **en amont** un compte de service SSH sur les cibles et
fournit la clé privée correspondante à l’API (`LINSEC_ANSIBLE_SSH_PRIVATE_KEY_PATH`).
LinSec360 ne scanne plus, n’épingle plus et ne compare plus d’empreinte SSH :
les déploiements, les tests de connexion et le terminal utilisent uniquement ce
compte de service.

Les anciens endpoints `fingerprint` restent importables pour compatibilité, mais
ne sont plus utilisés par l’interface ni par le worker Ansible.

## 2. Gestion des hôtes

- Ajout unitaire : nom/alias, IPv4, environnement, niveau, groupes, utilisateur
  SSH, port et référence de clé. Le bouton *Tester la connexion* appelle
  `POST /api/v1/hosts/test-connection` et détecte la distribution via Ansible.
- Import en masse : CSV avec en-têtes, JSON ou collage multi-lignes
  (`hostname,ip,ssh_user,group,environment`). Une prévisualisation valide les
  formats, signale les doublons et permet de désélectionner certaines lignes.
- Case *Déployer après ajout* : lance le playbook autorisé par défaut (`site.yml`
  si disponible) via l’endpoint de déploiement existant.
- CRUD hôtes : la référence de clé est stockée dans `hosts.ssh_key_reference` et
  exportée dans l’inventaire généré sous `linsec_ssh_key_reference`.

## 3. Terminal interactif

- `backend/api/terminal.py` expose
  `WS /api/v1/hosts/{id}/terminal/ws`.
- Authentification par cookie de session (ou token Bearer), rôle `admin` ou
  `operator` requis.
- Connexion SSH avec PTY local (`ssh -tt`), `stdin`/`stdout`/`stderr` temps réel
  et messages WebSocket `input`, `output`, `resize`.
- Journalisation : `host.terminal_open` et `host.terminal_close` dans la table
  d’audit avec utilisateur et hôte cible.
- Le proxy nginx `web/snippets/linsec-locations.conf` gère l’upgrade WebSocket
  pour `/api/v1/hosts/`.

## 4. Pilotage opérationnel

- Page Hôtes : compteurs (parc, conformité, patching), filtres par recherche,
  environnement, OS et statut, sélection multiple et actions groupées
  (agent Wazuh, contrôle MAC, nettoyage, audit, remédiation).
- Fiche hôte : statut Wazuh, livepatch, correctifs, redémarrage requis,
  séquence OpenSCAP *Auditer → Remédier → Re-contrôler* et accès au terminal.
- Page Conformité : mêmes étapes OpenSCAP avec confirmation explicite avant
  remédiation.
- Page Correctifs : vérification livepatch et application ciblée des correctifs.
- Les exécutions longues restent suivies via `/deployments`, leurs événements
  SSE et leurs logs détaillés.

## 5. Configuration requise

| Élément | Configuration |
| --- | --- |
| Compte de service | Créé hors de LinSec360, avec accès SSH par clé sur chaque cible. |
| Clé privée | `LINSEC_ANSIBLE_SSH_PRIVATE_KEY_PATH` dans l’API et le worker. |
| Terminal | API et worker doivent avoir `openssh-client` (déjà installé dans `backend/Dockerfile`). |
| Reverse proxy | Snippet nginx rechargé pour la location WebSocket. |
| Inventaire | Généré depuis la base ; aucun fichier statique à éditer à la main. |

Si un hôte n’est pas joignable, le test de connexion renvoie un message lisible
et l’interface n’affiche plus aucun écran de validation d’empreinte.
