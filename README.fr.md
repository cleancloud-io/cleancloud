# CleanCloud

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![Docker Pulls](https://img.shields.io/docker/pulls/getcleancloud/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
[![Security Scanning](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml)
![GitHub stars](https://img.shields.io/github/stars/cleancloud-io/cleancloud?style=social)

**Languages / Langues :**
🇬🇧 [English](README.md) | 🇫🇷 [Français](README.fr.md)

**Docs:** [Configuration AWS](docs/aws.md) · [Permissions & Commandes AWS](docs/aws.md#at-a-glance) · [Multi-comptes AWS](docs/aws.md#multi-account-scanning) · [Configuration Azure](docs/azure.md) · [Guide CI/CD](docs/ci.md) · [Règles de détection](docs/rules.md) · [Exemples de sortie](docs/example-outputs.md) · [Docker Hub](https://hub.docker.com/r/getcleancloud/cleancloud) · [GitHub Action](https://github.com/marketplace/actions/cleancloud-scan)

---

**Applique la politique d'hygiène cloud en CI et donne aux équipes engineering, finance et ops une vue unifiée du gaspillage.**

**Supporte :** AWS · Azure — GCP bientôt disponible

Hygiène cloud en lecture seule pour les environnements réglementés & souverains.

CleanCloud scanne votre environnement cloud et rapporte ce qui gaspille de l'argent. Exécutez-le une fois pour un audit ponctuel, planifiez-le, ou intégrez-le en CI/CD pour bloquer les builds sur des violations de politique.

- **20 règles de détection haut signal :** volumes orphelins, bases de données inactives, load balancers vides, et plus
- **Gaspillage mensuel estimé :** par finding et en agrégat, détaillé par compte et abonnement
- **Scan multi-comptes (AWS) :** scannez des AWS Organizations entières en quelques minutes — fichier de config, IDs inline, ou auto-découverte via `--org`
- **Scan multi-abonnements (Azure) :** scannez tous les abonnements Azure en parallèle avec une seule identité — auto-découverte via Management Group ou tous les accessibles — détail des coûts par abonnement inclus
- **Application de politique CI/CD (opt-in) :** `--fail-on-confidence HIGH` ou `--fail-on-cost 100` gate votre pipeline
- **Formats de sortie multiples :** lisible, JSON, CSV, et markdown (à coller dans vos PRs GitHub ou Slack)
- **Lecture seule par conception :** aucune suppression, aucune modification de tags, aucune mutation — jamais
- **Aucun agent. Zéro télémétrie. Pas de SaaS.** S'exécute dans votre environnement, les données ne quittent jamais votre périmètre

### Ce que CleanCloud ne fait PAS

| | |
|---|---|
| ❌ Supprimer des ressources | ❌ Modifier ou créer des tags |
| ❌ Écrire dans une API cloud | ❌ Stocker ou journaliser des credentials |
| ❌ Envoyer des données de télémétrie | ❌ Nécessiter un compte SaaS ou un agent |

Toutes les opérations sont en lecture seule. Sûr pour les comptes de production, environnements air-gapped, et pipelines soumis à revue de sécurité.

**Cas d'usage :**
- Audit ponctuel de gaspillage cloud — exécutez dans CloudShell, findings visibles en 60 secondes
- Analyses d'hygiène planifiées — cron ou CI hebdomadaire pour détecter la dérive
- Gate CI/CD — bloquer un build si le gaspillage dépasse votre seuil

```
6 problèmes d'hygiène détectés :

1. [AWS] Volume EBS non attaché      — $40/mois
2. [AWS] NAT Gateway inactive        — $32.40/mois
3. [AWS] Elastic IP non attachée     — $0/mois
...

Gaspillage mensuel estimé : ~$147
Régions scannées : us-east-1, us-west-2, eu-west-1
```

## Mentionné dans la presse

- [Korben](https://korben.info/cleancloud-nettoyeur-cloud-aws-azure.html) 🇫🇷 — Grand média tech français
- [Last Week in AWS #457](https://www.lastweekinaws.com/newsletter/15259/) — La newsletter AWS de Corey Quinn

## Ce qu'en disent les utilisateurs

> "Outil de découverte solide qui remonte les économies potentielles. Facile à installer et à utiliser !"
> — [Utilisateur Reddit](https://www.reddit.com/r/AZURE/comments/1rm7an5/comment/o8zfv6a/)

---

## Démarrage

### Commandes

| Commande | Fonction |
|---|---|
| `cleancloud demo` | Affiche des findings exemples — aucun credential requis |
| `cleancloud scan` | Scanne votre environnement cloud et rapporte les findings |
| `cleancloud doctor` | Vérifie que les credentials et permissions sont correctement configurés |
| `cleancloud --version` | Affiche la version installée |
| `cleancloud --help` | Liste tous les flags |

<details>
<summary>Tous les flags de scan</summary>

```
# Obligatoire
--provider aws|azure          Fournisseur cloud à scanner

# Région (optionnel)
--region REGION               Région unique
--all-regions                 Scanne toutes les régions actives (recommandé)

# Multi-comptes — AWS uniquement (optionnel, choisir un)
--multi-account FILE          Fichier de config listant les comptes (ex. .cleancloud/accounts.yaml)
--accounts 111,222            IDs de comptes inline, séparés par des virgules
--org                         Auto-découverte via AWS Organizations
--concurrency N               Comptes en parallèle (défaut : 3)
--timeout SECONDS             Timeout total du scan en secondes (défaut : 3600)

# Multi-abonnements — Azure uniquement (optionnel)
--management-group ID         Scanner tous les abonnements d'un Management Group
--subscription ID             Scanner un seul abonnement (défaut : tous les accessibles)

# Sortie (optionnel)
--output human|json|csv|markdown  Format de sortie (défaut : human)
--output-file FILE            Écrit la sortie dans un fichier

# Application CI/CD (optionnel, tous retournent exit code 2)
--fail-on-confidence HIGH     Échec sur findings HIGH confidence
--fail-on-confidence MEDIUM   Échec sur findings MEDIUM ou supérieur
--fail-on-cost N              Échec si gaspillage mensuel estimé >= $N
--fail-on-findings            Échec si au moins un finding
```

</details>

**Via pipx (recommandé pour usage local) :**
```bash
pipx install cleancloud
pipx ensurepath        # ajoute cleancloud au PATH — relancez votre shell après
cleancloud demo        # visualisez des findings sans aucun credential cloud
```

**Via Docker (recommandé pour CI/CD — Python non requis) :**
```bash
docker pull getcleancloud/cleancloud
docker run --rm getcleancloud/cleancloud demo

# Avec credentials AWS (Docker n'hérite pas de ~/.aws automatiquement)
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_REGION=us-east-1 \
  getcleancloud/cleancloud scan --provider aws --all-regions
```

> En CI/CD, `aws-actions/configure-aws-credentials` définit les variables `AWS_*` sur le runner — passez-les avec `-e VAR_NAME` et elles sont transmises au conteneur automatiquement. Voir [Guide CI/CD →](docs/ci.md#using-the-docker-image)

Prêt à scanner votre vrai environnement ? Authentifiez-vous d'abord, puis lancez :

```bash
# AWS : assurez-vous d'être connecté (aws configure, aws sso login, ou rôle IAM)
cleancloud scan --provider aws --all-regions

# Azure : assurez-vous d'être connecté (az login)
cleancloud scan --provider azure
```

Pas sûr que vos credentials aient les bonnes permissions ? Lancez d'abord `cleancloud doctor --provider aws` ou `cleancloud doctor --provider azure`.

### Sans installation — essayez dans votre cloud shell

Vous avez un compte AWS ou Azure ? Lancez un vrai scan en quelques secondes, sans installation locale.

**AWS — [AWS CloudShell](https://console.aws.amazon.com/cloudshell) :**
```bash
pip install --upgrade cleancloud
cleancloud doctor --provider aws   # vérifiez les permissions de votre session
cleancloud scan --provider aws --all-regions
```

**Azure — [Azure Cloud Shell](https://shell.azure.com) :**
```bash
pip install --upgrade --user cleancloud
export PATH="$HOME/.local/bin:$PATH"
cleancloud doctor --provider azure  # vérifiez les permissions de votre session
cleancloud scan --provider azure
```

Les deux shells s'authentifient via votre session du portail — aucune credential séparée n'est requise.

Les permissions varient selon les comptes ; `doctor` vous indique exactement ce qui est disponible avant de scanner. Si des permissions sont manquantes, CleanCloud ignore les règles concernées et indique lesquelles ont été ignorées.

<details>
<summary>Problèmes d'installation</summary>

**macOS :** `brew install pipx && pipx install cleancloud`

**Linux :** `sudo apt install pipx && pipx install cleancloud`

**Windows :** `python3 -m pip install --user pipx && python3 -m pipx ensurepath && pipx install cleancloud`

**Command not found: cleancloud** — Exécutez `pipx ensurepath` puis relancez votre shell.

**externally-managed-environment** — Utilisez `pipx` à la place de `pip`.

**Mise à jour depuis un `pip install` existant** — supprimez-le d'abord pour éviter les conflits :
```bash
pip uninstall cleancloud && pipx install cleancloud && pipx ensurepath
```

**Mauvaise version après installation** — Exécutez `which cleancloud` ; un ancien `pip install` masque peut-être le pipx.

**Version minimale recommandée : v1.7.2** — les versions antérieures ont des problèmes de setup. Exécutez `cleancloud --version` pour vérifier.

</details>

---

## Exemple de résultat détaillé

```
6 problèmes d'hygiène détectés :

1. [AWS] Volume EBS non attaché
   Risque     : Faible
   Confiance  : High
   Ressource  : aws.ebs.volume → vol-0a1b2c3d4e5f67890
   Région     : us-east-1
   Règle      : aws.ebs.volume.unattached
   Raison     : Volume non attaché depuis 47 jours
   Détails :
     - size_gb: 500
     - state: available
     - tags: {"Project": "legacy-api", "Owner": "platform"}

2. [AWS] NAT Gateway inactive
   Risque     : Moyen
   Confiance  : Medium
   Ressource  : aws.ec2.nat_gateway → nat-0abcdef1234567890
   Région     : us-west-2
   Règle      : aws.ec2.nat_gateway.idle
   Raison     : Aucun trafic détecté depuis 21 jours
   Détails :
     - name: staging-nat
     - total_bytes_out: 0
     - estimated_monthly_cost_usd: 32.40

3. [AWS] Elastic IP non attachée
   Risque     : Faible
   Confiance  : High
   Ressource  : aws.ec2.elastic_ip → eipalloc-0a1b2c3d4e5f6
   Région     : eu-west-1
   Règle      : aws.ec2.elastic_ip.unattached
   Raison     : Elastic IP non associée à aucune instance ou ENI (ancienneté : 92 jours)

--- Résumé du scan ---
Total findings : 6
Par risque :     faible: 5  moyen: 1
Par confiance :  high: 2  medium: 4
Gaspillage minimum estimé : ~$147/mois
(4 findings sur 6 chiffrés)
Régions scannées : us-east-1, us-west-2, eu-west-1 (auto-détectées)
```

Pas encore de compte cloud ? `cleancloud demo` affiche un exemple de sortie sans aucun credential.

### Rapport markdown partageable

```bash
cleancloud scan --provider aws --all-regions --output markdown
```

Produit un résumé groupé que vous pouvez coller directement dans un commentaire de PR GitHub, un message Slack, ou une issue :

```markdown
## Résultats du scan CleanCloud

**Provider :** AWS
**Régions :** us-east-1, us-west-2, eu-west-1
**Scanné le :** 2026-03-07
**Gaspillage mensuel estimé :** ~$147

**Total des findings :** 6

| Finding | Nombre | Coût mensuel estimé |
|---------|-------:|--------------------:|
| Volume EBS non attaché | 2 | ~$115 |
| NAT Gateway inactive | 1 | ~$32 |
| Elastic IP non attachée | 1 | ~$0 |
| ENI détachée | 1 | — |
| CloudWatch Log Group : rétention infinie | 1 | — |

**Confiance :** high: 3 · medium: 3

> Généré par [CleanCloud](https://github.com/cleancloud-io/cleancloud) — scanner d'hygiène cloud lecture seule pour AWS et Azure.
```

Sauvegardez dans un fichier avec `--output-file results.md`. Sans `--output-file`, la sortie s'affiche dans stdout.

Pour des exemples de sortie complets incluant `doctor`, JSON, CSV et markdown : [`docs/example-outputs.md`](docs/example-outputs.md)

---

## Ce que CleanCloud détecte

20 règles pour AWS et Azure — conservatives, haut signal, conçues pour éviter les faux positifs en environnements IaC.

**AWS :**
- Volumes EBS non attachés (HIGH)
- Anciens snapshots EBS
- Logs CloudWatch à rétention infinie
- Elastic IPs non attachées (HIGH)
- ENI détachées
- Ressources sans tags
- Anciennes AMIs
- NAT Gateways inactives
- Instances RDS inactives (HIGH)
- Load Balancers inactifs (HIGH)

**Azure :**
- Disques managés non attachés
- Anciens snapshots
- Adresses IP publiques inutilisées (HIGH)
- Load Balancers vides (HIGH)
- App Gateways vides (HIGH)
- App Service Plans vides (HIGH)
- VNet Gateways inactives
- VMs arrêtées (non désallouées) (HIGH)
- Bases de données SQL inactives (HIGH)
- Ressources sans tags

Les règles sans marqueur de confiance sont MEDIUM — elles utilisent des heuristiques temporelles ou des signaux multiples. Commencez par `--fail-on-confidence HIGH` pour les gaspillages évidents, puis resserrez au fil de la validation par votre équipe.

**Détails complets des règles, signaux et preuves :** [`docs/rules.md`](docs/rules.md)

---

## Application de politique CI/CD

Les scans se terminent avec `0` par défaut. Activez l'application de politique :

| Flag | Comportement | Code de sortie |
|------|-------------|----------------|
| *(aucun)* | Rapport uniquement, jamais d'échec | `0` |
| `--fail-on-confidence HIGH` | Échec sur les findings HIGH | `2` |
| `--fail-on-confidence MEDIUM` | Échec sur MEDIUM ou supérieur | `2` |
| `--fail-on-cost 50` | Échec si gaspillage mensuel estimé >= 50$ | `2` |
| `--fail-on-findings` | Échec sur n'importe quel finding | `2` |

Workflows GitHub Actions complets et prêts à l'emploi pour AWS (OIDC) et Azure (Workload Identity) — incluant la configuration OIDC, les politiques IAM/RBAC, et les patterns d'application :

**[Guide CI/CD →](docs/ci.md)** · [Configuration AWS →](docs/aws.md) · [Configuration Azure →](docs/azure.md)

**Besoin d'aide avec OIDC ou les flags d'application ?** [Posez votre question dans notre discussion CI/CD →](https://github.com/cleancloud-io/cleancloud/discussions/98)

---

## Scan Multi-Comptes (AWS uniquement)

Conçu pour les entreprises utilisant AWS Organizations. Scannez chaque compte en parallèle — les findings sont agrégés dans un seul rapport.

```bash
# Scan depuis un fichier de configuration (commitez .cleancloud/accounts.yaml dans votre repo)
cleancloud scan --provider aws --multi-account .cleancloud/accounts.yaml --all-regions

# IDs de comptes en ligne — sans fichier
cleancloud scan --provider aws --accounts 111111111111,222222222222 --all-regions

# Auto-découverte de tous les comptes de votre AWS Organization
cleancloud scan --provider aws --org --all-regions --concurrency 5
```

**Permissions requises :**

| Rôle | Permissions |
|---|---|
| Compte hub | 16 permissions lecture seule + `sts:AssumeRole` sur les rôles spoke |
| Compte hub (`--org` uniquement) | Ci-dessus + `organizations:ListAccounts` |
| Comptes spoke | 16 permissions lecture seule (identique au scan mono-compte — aucun changement) |

**`.cleancloud/accounts.yaml`** — à commiter dans votre repo :

```yaml
role_name: CleanCloudReadOnlyRole
accounts:
  - id: "111111111111"
    name: production
  - id: "222222222222"
    name: staging
```

**Trust policy du compte spoke** — autorise le hub à assumer le rôle :

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<HUB_ACCOUNT_ID>:root" },
  "Action": "sts:AssumeRole"
}
```

Politique IAM complète, trust policy et templates IaC : [Configuration multi-comptes AWS →](docs/aws.md#multi-account-scanning)

**Comment ça fonctionne :**

- **Hub-and-spoke** — CleanCloud assume `CleanCloudReadOnlyRole` dans chaque compte cible via STS. Aucun accès persistant, aucun credential stocké.
- **Trois modes de découverte** — `.cleancloud/accounts.yaml` pour un contrôle explicite, `--accounts` pour des scans ad-hoc rapides, `--org` pour l'auto-découverte complète via AWS Organizations.
- **Détection de régions efficace** — les régions actives sont découvertes une seule fois sur le compte hub et réutilisées sur tous les spokes. Sans ça : N comptes × 160 appels API rien que pour la détection de régions. Avec : 160 appels une fois.
- **Parallèle avec isolation** — chaque compte s'exécute dans son propre thread avec sa propre session. Un compte en échec (AccessDenied, timeout) n'affecte jamais les autres.
- **Visibilité partielle** — si 2 régions échouent et 7 réussissent dans un compte, le compte est marqué `partial` avec les régions en échec nommées. Vous voyez exactement ce qui a été manqué.
- **Progression en temps réel** — `[3/50] done production (123456789012) — 47s, 12 findings` affiché au fil des comptes.
- **Détail des coûts par compte** — la sortie JSON inclut le gaspillage mensuel estimé par compte.

Guide complet (politique IAM, trust policy, templates IaC) : [Configuration multi-comptes AWS →](docs/aws.md#multi-account-scanning)

---

## Scan multi-abonnements (Azure)

Conçu pour les entreprises gérant de grands tenants Azure. Scannez chaque abonnement en parallèle avec une seule identité — findings agrégés dans un rapport unique avec détail des coûts par abonnement.

```bash
# Scanner tous les abonnements accessibles (défaut)
cleancloud scan --provider azure

# Auto-découverte via Management Group
cleancloud scan --provider azure --management-group <MANAGEMENT_GROUP_ID>

# Liste explicite
cleancloud scan --provider azure --subscription <SUB_1> --subscription <SUB_2>
```

**Permissions requises :**

| Périmètre | Rôle |
|---|---|
| Chaque abonnement | Reader (intégré) |
| Management Group (si `--management-group`) | Reader + `Microsoft.Management/managementGroups/read` |

Assignez Reader au niveau du Management Group — il hérite automatiquement à tous les abonnements en dessous :

```bash
az role assignment create \
  --assignee <SERVICE_PRINCIPAL_CLIENT_ID> \
  --role Reader \
  --scope /providers/Microsoft.Management/managementGroups/<MANAGEMENT_GROUP_ID>
```

**Fonctionnement :**

- **Modèle d'identité plat** — un seul service principal, Reader au niveau du Management Group. Pas d'assumption de rôle inter-abonnements, pas de complexité hub-and-spoke.
- **Trois modes de découverte** — tous les accessibles (défaut), `--management-group` pour l'auto-découverte, `--subscription` pour un contrôle explicite.
- **Parallèle avec isolation** — chaque abonnement s'exécute dans son propre thread. Un abonnement en échec (permission refusée, timeout) n'affecte jamais les autres.
- **Gestion gracieuse des permissions** — les règles échouant avec 403 sont signalées comme ignorées (avec la permission manquante nommée), pas comme des échecs de scan.
- **Détail des coûts par abonnement** — la sortie indique le gaspillage mensuel estimé par abonnement pour identifier précisément lequel est problématique.

Guide complet (RBAC, Workload Identity, Management Group) : [Configuration multi-abonnements Azure →](docs/azure.md#multi-subscription-scanning)

---

## Feuille de route

- Règles AWS supplémentaires (cycle de vie S3, instances EC2 arrêtées)
- Policy-as-code dans `cleancloud.yaml` (`fail_on_confidence`, `fail_on_cost` en config)
- Filtrage de règles (flag `--rules`)

---

## Documentation

- [`docs/rules.md`](docs/rules.md) — Règles de détection, signaux et preuves
- [`docs/aws.md`](docs/aws.md) — Politique IAM AWS et configuration OIDC
- [`docs/azure.md`](docs/azure.md) — RBAC Azure et configuration Workload Identity
- [`docs/ci.md`](docs/ci.md) — Guide d'intégration CI/CD
- [`docs/example-outputs.md`](docs/example-outputs.md) — Exemples de sortie complets
- [`SECURITY.md`](SECURITY.md) — Politique de sécurité et modèle de menace
- [`docs/infosec-readiness.md`](docs/infosec-readiness.md) — IAM Proof Pack, modèle de menace

---

**Vous avez trouvé un bug ?** [Ouvrez une issue](https://github.com/cleancloud-io/cleancloud/issues)

**Demande de fonctionnalité ?** [Démarrez une discussion](https://github.com/cleancloud-io/cleancloud/discussions)

**Questions ?** suresh@getcleancloud.com

[Licence MIT](LICENSE)
