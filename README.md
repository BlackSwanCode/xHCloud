# ☁️ xHCloud — Suite de Pentest Cloud & API

**xHCloud** est un framework CLI en Python (asynchrone, basé sur `httpx` + `asyncio`) qui regroupe en un seul outil plusieurs techniques classiques de reconnaissance et d'audit "Cloud" :

- génération et résolution DNS massive de permutations de noms d'hôtes Cloud (AWS / Azure / GCP),
- détection de buckets de stockage mal configurés (S3, Azure Blob, GCS) et de leurs équivalents cross-cloud,
- audit de surface d'API (GraphQL, NoSQL, Serverless, Azure AD / OpenID),
- audit de surface web générique (fichiers sensibles exposés, en-têtes de sécurité manquants),
- génération de rapports HTML/JSON exploitables.

Le tableau de bord (`rich`) affiche en temps réel la progression des scans et les vulnérabilités trouvées.

> ⚠️ **Avertissement légal** — xHCloud envoie des requêtes actives (y compris des tentatives d'injection NoSQL, de bypass d'authentification et de brute-force de clés serverless) vers les cibles scannées. **N'utilisez cet outil que sur des systèmes que vous possédez ou pour lesquels vous avez une autorisation écrite explicite.** Scanner une cible sans autorisation peut être illégal selon votre juridiction (en France : articles 323-1 et suivants du Code pénal). Ce README n'utilise que des plateformes publiques **conçues pour être testées légalement** : [testphp.vulnweb.com](http://testphp.vulnweb.com) (Acunetix) et [testfire.net](http://testfire.net) (IBM AltoroMutual).

---

## Sommaire

1. [Architecture du projet](#architecture-du-projet)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Les 4 modules](#les-4-modules)
5. [Exemples d'utilisation sur cibles autorisées](#exemples-dutilisation-sur-cibles-autorisées)
6. [Rapports générés](#rapports-générés)
7. [Limites connues & bonnes pratiques](#limites-connues--bonnes-pratiques)

---

## Architecture du projet

```
xHCloud-main/
├── setup.py                      # Packaging, point d'entrée console "xhcloud"
└── xhcloud/
    ├── cli.py                    # Point d'entrée Typer : recon / storage / api / audit
    ├── ifos.txt
    ├── core/
    │   ├── engine.py              # Client HTTP async (httpx) + config globale
    │   ├── ui.py                  # Dashboard temps réel (rich.Live)
    │   └── reporter.py            # Génération de rapports HTML / JSON
    └── modules/
        ├── recon/generator.py     # Permutations de noms Cloud + résolution DNS async
        ├── storage/scanner.py     # Détection buckets S3 / Azure Blob / GCS publics
        ├── api/scanner.py         # GraphQL, NoSQL, Serverless, Azure AD
        └── audit/scanner.py       # Fichiers sensibles + en-têtes de sécurité HTTP
```

Le flux général d'une commande est toujours le même :

1. `XHCloudConfig` charge `config.yaml` (ou des valeurs par défaut).
2. `XHCloudDashboard` initialise l'interface temps réel.
3. `XHCloudEngine` crée un client `httpx.AsyncClient` partagé (proxy, timeout, User-Agent, TLS).
4. Le scanner du module (`recon`, `storage`, `api` ou `audit`) consomme ce client avec un `asyncio.Semaphore` pour borner la concurrence.
5. Chaque trouvaille est poussée dans `dashboard.findings`, affichée en direct, puis (pour `audit`) exportée via `ReportGenerator`.

---

## Installation

```bash
git clone https://github.com/<votre-compte>/xHCloud.git
cd xHCloud
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

Cela installe les dépendances déclarées dans `setup.py` (`rich`, `typer`, `httpx`, `pyyaml`) et expose la commande `xhcloud` dans votre PATH.

Vérification :

```bash
xhcloud --help
```

Vous devez voir les 4 sous-commandes : `recon`, `storage`, `api`, `audit`.

---

## Configuration

Au lancement, `XHCloudConfig` cherche un fichier `config.yaml` dans le répertoire courant. S'il n'existe pas, ces valeurs par défaut sont utilisées :

```yaml
proxy: null                                   # ex: "http://127.0.0.1:8080" pour router vers Burp/ZAP
timeout: 10
threads: 50
user_agent: "xHCloud/1.0 (Cloud Pentest Suite)"
verify_ssl: false
```

Créez votre propre `config.yaml` à la racine de votre répertoire de travail pour, par exemple, faire passer tout le trafic par un proxy d'interception :

```yaml
proxy: "http://127.0.0.1:8080"
timeout: 15
threads: 20
user_agent: "Mozilla/5.0 (xHCloud-Lab)"
verify_ssl: false
```

---

## Les 4 modules

### 1. `recon` — Découverte d'infrastructure Cloud

Génère des permutations de noms d'hôtes basées sur le nom d'une entreprise (extrait automatiquement du domaine fourni), puis les résout en DNS pour ne garder que les hôtes vivants.

```bash
xhcloud recon <domaine_ou_fichier> [OPTIONS]
```

| Option | Description | Défaut |
|---|---|---|
| `--providers / -p` | Liste CSV des providers à cibler (`aws`, `azure`, `gcp`) | `aws,azure,gcp` |
| `--keywords / -k` | Active les mutations par mots-clés (dev, staging, backup…) | désactivé |
| `--dns / --no-dns` | Active/désactive la résolution DNS des permutations | `--dns` |

Résultat : fichier `xhcloud_recon_output.txt` contenant les hôtes trouvés (ou toutes les permutations générées si `--no-dns`).

### 2. `storage` — Scan de stockage Cloud public

Teste des URLs de buckets S3 / conteneurs Azure Blob / buckets GCS pour un accès anonyme en listing, et peut muter automatiquement une URL vers les autres fournisseurs Cloud (ex. tester l'équivalent Azure d'un bucket S3).

```bash
xhcloud storage <fichier_urls.txt> [OPTIONS]
```

| Option | Description | Défaut |
|---|---|---|
| `--mutate / --no-mutate` | Active la génération d'URLs cross-cloud | `--mutate` |
| `--threads / -t` | Nombre de requêtes concurrentes | `50` |

### 3. `api` — Audit de surface API & Serverless

Oriente automatiquement les tests selon le pattern de l'URL :
- endpoints `/graphql`, `/graphiql`, `/playground` → tests d'introspection GraphQL,
- domaines `azurefunctions.net` / `azurewebsites.net` / `lambda-url.amazonaws.com` → brute-force léger des clés d'administration serverless par défaut,
- toute URL → tentative d'injection NoSQL / pollution de prototype sur les requêtes POST JSON,
- domaines contenant `azure` / `microsoftonline` → vérification de la configuration `.well-known/openid-configuration`.

```bash
xhcloud api <fichier_urls.txt> [OPTIONS]
```

| Option | Description | Défaut |
|---|---|---|
| `--aggressive / -a` | Active des tests de fuzzing plus lourds | désactivé |
| `--threads / -t` | Nombre de requêtes concurrentes | `30` |

### 4. `audit` — Audit de surface web générique

Vérifie l'exposition de fichiers sensibles (`.git/config`, `.env`, `.aws/credentials`, `swagger.json`, `phpinfo.php`…) et la présence des en-têtes de sécurité HTTP recommandés (`Strict-Transport-Security`, `Content-Security-Policy`, etc.).

```bash
xhcloud audit <fichier_urls.txt> [OPTIONS]
```

| Option | Description | Défaut |
|---|---|---|
| `--report / -r` | Format du rapport : `html`, `json`, ou `all` | `html` |

---

## Exemples d'utilisation sur cibles autorisées

Les deux cibles ci-dessous sont des applications volontairement vulnérables, publiées par leurs éditeurs pour l'entraînement à la sécurité :

- **testphp.vulnweb.com** — application PHP de démonstration maintenue par Acunetix.
- **testfire.net** — "AltoroMutual", banque fictive de démonstration maintenue par IBM (HCL AppScan).

> Même sur ces cibles « bac à sable », restez raisonnable sur le volume de requêtes (`--threads` modéré) par courtoisie envers l'infrastructure partagée des éditeurs.

### Exemple 1 — Audit de surface avec `audit`

Créez un fichier de cibles :

```bash
cat > targets_audit.txt << 'EOF'
http://testphp.vulnweb.com
http://testfire.net
EOF
```

Lancez l'audit avec export complet (HTML + JSON) :

```bash
xhcloud audit targets_audit.txt --report all
```

Résultat attendu (le tableau de bord s'affiche en temps réel, puis) :
- `xhcloud_report.html` : rapport visuel avec compteurs par sévérité.
- `xhcloud_report.json` : mêmes données en JSON pour intégration CI/CD.

Ce module devrait notamment signaler sur `testphp.vulnweb.com` l'absence d'en-têtes de sécurité modernes (`Content-Security-Policy`, `Strict-Transport-Security`), ce site datant volontairement d'une époque antérieure aux bonnes pratiques actuelles.

### Exemple 2 — Scan API/NoSQL avec `api`

`testphp.vulnweb.com` expose des scripts PHP classiques qui acceptent des paramètres en POST — utile pour illustrer le module NoSQL/JSON :

```bash
cat > targets_api.txt << 'EOF'
http://testphp.vulnweb.com/login.php
http://testfire.net/bank/login.aspx
EOF

xhcloud api targets_api.txt --threads 10
```

Le scanner enverra des payloads JSON (opérateurs `$ne`, `$gt`, pollution de prototype `__proto__`) à chaque cible en POST et signalera toute réponse contenant des indices de bypass (`welcome`, `success`, `admin`, `true`…). Sur des endpoints qui n'acceptent pas le JSON, ces tests n'auront simplement aucun effet (comportement attendu, pas une erreur).

### Exemple 3 — Reconnaissance Cloud avec `recon`

```bash
xhcloud recon vulnweb.com --providers aws,azure,gcp --keywords
```

`extract_company_name` isolera `vulnweb` du domaine fourni, puis générera des permutations telles que `vulnweb.s3.amazonaws.com`, `vulnweb.blob.core.windows.net`, `dev-vulnweb.azurewebsites.net`, etc., avant de les résoudre en DNS. Le fichier `xhcloud_recon_output.txt` contiendra les hôtes effectivement résolus — à titre d'exercice, la plupart n'existeront pas, ce qui est normal : ce module sert à illustrer la technique de permutation + résolution de masse, pas à garantir des résultats sur ce domaine précis.

### Exemple 4 — Scan de stockage avec `storage`

```bash
cat > targets_storage.txt << 'EOF'
https://vulnweb.s3.amazonaws.com
EOF

xhcloud storage targets_storage.txt --mutate --threads 20
```

Avec `--mutate` activé, l'URL S3 ci-dessus sera automatiquement déclinée en équivalents Azure Blob et CloudFront avant d'être testée, afin d'illustrer la logique de mutation cross-cloud même quand on ne connaît que le nom d'un bucket sur un seul fournisseur.

### Exemple 5 — Chaîner les modules

Un flux complet typique : reconnaissance → audit de surface → rapport.

```bash
xhcloud recon testphp.vulnweb.com --no-dns
xhcloud audit xhcloud_recon_output.txt --report all
```

---

## Rapports générés

Le module `audit` (via `core/reporter.py`) produit :

- **`xhcloud_report.html`** : page autonome en thème sombre, avec compteurs `Critical / High / Medium / Low` et tableau détaillé (sévérité, module, cible, détails).
- **`xhcloud_report.json`** : la même liste de `findings` au format `{severity, module, target, details}`, pratique pour une intégration dans un pipeline CI ou un autre outil.

Les autres modules (`recon`, `storage`, `api`) affichent leurs résultats dans le dashboard en temps réel ; `recon` écrit en plus un export texte brut (`xhcloud_recon_output.txt`).

---

## Limites connues & bonnes pratiques

- **`verify_ssl: false` par défaut** : pratique en laboratoire, mais à réactiver (`verify_ssl: true`) si vous auditez des cibles réelles pour éviter de masquer des erreurs de certificat pertinentes.
- **Détections par mots-clés** : plusieurs modules (NoSQL, `.env`) se basent sur la présence de chaînes comme `welcome`, `success`, `DB_` dans la réponse — attendez-vous à des faux positifs/négatifs selon l'application testée ; validez manuellement chaque trouvaille `Critical`/`High` avant de la considérer confirmée.
- **Dictionnaire de régions/services réduit** dans `recon/generator.py` (`CLOUD_PROVIDERS`) : volontairement limité, à étendre selon vos besoins (davantage de régions AWS, de services GCP, etc.).
- **Rate limiting** : ajustez `--threads` et `timeout` (dans `config.yaml`) pour rester courtois sur les cibles partagées comme vulnweb.com/testfire.net, et pour éviter les faux négatifs liés à des réponses de type 429/503.
- **Usage responsable** : exécutez systématiquement ces commandes dans un périmètre autorisé — environnements de lab personnels, programmes de bug bounty avec scope explicite, ou plateformes publiques prévues à cet effet comme celles citées plus haut.
