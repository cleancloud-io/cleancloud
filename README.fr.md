# CleanCloud

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**Languages / Langues :**
🇬🇧 [English](README.md) | 🇫🇷 [Français](README.fr.md)

**Docs:** [Configuration AWS](docs/aws.md) · [Permissions & Commandes AWS](docs/aws.md#at-a-glance) · [Multi-comptes AWS](docs/aws.md#multi-account-scanning) · [Configuration Azure](docs/azure.md) · [Configuration GCP](docs/gcp.md) · [Guide CI/CD](docs/ci.md) · [Règles de détection](docs/rules.md) · [Exemples de sortie](docs/example-outputs.md) · [Docker Hub](https://hub.docker.com/r/getcleancloud/cleancloud) · [GitHub Action](https://github.com/marketplace/actions/cleancloud-scan)

---

**CleanCloud est le moteur d'hygiène cloud — la couche manquante entre la visibilité des coûts et le nettoyage.**

**Supporte :** AWS · Azure · GCP

Le gaspillage cloud a atteint 29% des dépenses en 2026 — première hausse en cinq ans (Flexera). La plupart des équipes ont déjà des tableaux de bord de coûts. Les tableaux de bord montrent les tendances de dépenses — ils n'indiquent pas aux ingénieurs ce qu'il faut nettoyer. Les plateformes FinOps SaaS nécessitent un accès vendor à votre compte cloud — exclu pour les industries réglementées. Et à mesure que les environnements cloud s'étendent sur plusieurs comptes et abonnements, les ressources inutilisées ne sont plus des exceptions — elles sont une dérive continue. Les équipes platform ont besoin d'un processus déterministe et applicable pour transformer cette dérive en une liste précise de ce sur quoi agir.

C'est CleanCloud. Scannez vos environnements AWS, Azure et GCP, obtenez des findings actionnables avec des estimations de coût par ressource, et appliquez des seuils de gaspillage sur un planning — aucun agent, aucun SaaS, aucune donnée ne quitte votre environnement.

| | Outils natifs AWS/Azure/GCP | Plateformes FinOps SaaS | **CleanCloud** |
|---|:---:|:---:|:---:|
| Affiche les tendances de coûts | ✅ | ✅ | — |
| Nomme exactement les ressources à nettoyer | ❌ | partiel | ✅ |
| Estimation de coût déterministe par ressource | ❌ | ❌ | ✅ |
| Lecture seule, aucun agent | ✅ | ❌ | ✅ |
| Fonctionne en environnements air-gapped / réglementés | ❌ | ❌ | ✅ |
| Aucun compte SaaS ni accès vendor requis | ❌ | ❌ | ✅ |
| Hygiène multi-comptes / multi-abonnements / multi-projets | ❌ | ✅ | ✅ |
| Application planifiée et CI/CD (codes de sortie) | ❌ | ❌ | ✅ |

- **32 règles de détection sélectives et haut signal :** volumes orphelins, bases de données inactives, instances arrêtées, registres inutilisés, et plus — conçues pour éviter les faux positifs en environnements IaC, chacune avec une estimation de coût déterministe. Les règles IA/ML (SageMaker, Azure ML) sont opt-in via `--category ai`
- **Gouvernance et application de politique (opt-in) :** `--fail-on-confidence HIGH` ou `--fail-on-cost 100` — appliquer des seuils de gaspillage sur un planning, géré par les équipes platform ou FinOps
- **Scan multi-comptes (AWS) :** scannez des AWS Organizations entières en une exécution — fichier de config, IDs inline, ou auto-découverte via `--org`
- **Scan multi-abonnements (Azure) :** scannez tous les abonnements Azure en parallèle — auto-découverte via Management Group, détail des coûts par abonnement inclus
- **Scan multi-projets (GCP) :** scannez tous les projets GCP accessibles en parallèle — auto-découverte via Application Default Credentials, détail des coûts par projet inclus
- **Sûr pour les environnements réglementés :** lecture seule, aucun agent, zéro télémétrie, pas de SaaS — s'exécute entièrement dans votre propre infrastructure. Adapté aux comptes de services financiers, de santé et gouvernementaux où l'accès SaaS tiers est restreint
- **Sortie prête pour l'écosystème :** JSON pour alertes Slack, tableaux de bord de coûts et automatisation des tickets — CSV pour les workflows tableur — markdown à coller directement dans vos PRs GitHub, Jira ou Confluence
- **Aucun agent. Zéro télémétrie. Pas de SaaS.** Les données ne quittent jamais votre environnement

### Ce que CleanCloud ne fait PAS

| | |
|---|---|
| ❌ Supprimer des ressources | ❌ Modifier ou créer des tags |
| ❌ Écrire dans une API cloud | ❌ Stocker ou journaliser des credentials |
| ❌ Envoyer des données de télémétrie | ❌ Nécessiter un compte SaaS ou un agent |

Toutes les opérations sont en lecture seule. Sûr pour les comptes de production, environnements air-gapped, et pipelines soumis à revue de sécurité.

**À qui s'adresse CleanCloud :**
- **Équipes platform et FinOps** — scans d'hygiène hebdomadaires sur votre AWS Org ou tenant Azure, application de seuils de gaspillage, détection de la dérive avant qu'elle ne s'accumule
- **Industries réglementées** — services financiers, santé et gouvernement qui ne peuvent pas envoyer les données de compte cloud à un fournisseur SaaS
- **Équipes mid-market** — trop grandes pour ignorer le gaspillage cloud, trop légères pour des plateformes FinOps enterprise. Les outils natifs montrent les factures ; CleanCloud montre ce qu'il faut corriger
- **Consultants cloud et MSPs** — audit en lecture seule d'un compte client en quelques minutes, export des findings en markdown ou JSON

**Cas d'usage :**
- Audit ponctuel de gaspillage cloud — exécutez dans CloudShell, findings visibles en 60 secondes
- Gouvernance d'hygiène planifiée — job hebdomadaire qui détecte les nouveaux gaspillages et applique les seuils sur tous les comptes
- Rapports pré-revue — exportez les findings en markdown avant une revue trimestrielle des coûts ou un board meeting

## Exemple de résultat détaillé

```
6 problèmes détectés :

1. [AWS] Instance RDS inactive (aucune connexion depuis 21 jours)
   Risque     : Élevé
   Confiance  : High
   Ressource  : aws.rds.instance → db-prod-analytics
   Région     : us-east-1
   Règle      : aws.rds.instance.idle
   Raison     : Instance RDS sans connexion depuis 21 jours
   Détails :
     - instance_class: db.r5.large
     - engine: postgres 15.4
     - estimated_monthly_cost: ~$380/mois

2. [AWS] Volume EBS non attaché
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

3. [AWS] NAT Gateway inactive
   Risque     : Moyen
   Confiance  : Medium
   Ressource  : aws.ec2.nat_gateway → nat-0abcdef1234567890
   Région     : us-west-2
   Règle      : aws.ec2.nat_gateway.idle
   Raison     : Aucun trafic détecté depuis 21 jours
   Détails :
     - name: staging-nat
     - total_bytes_out: 0
     - estimated_monthly_cost: ~$32/mois

4. [AWS] Load Balancer inactif (aucune cible saine)
   Risque     : Moyen
   Confiance  : High
   Ressource  : aws.elbv2.load_balancer → alb-staging-api
   Région     : us-east-1
   Règle      : aws.elbv2.load_balancer.idle
   Raison     : Load balancer sans cible saine depuis 30 jours
   Détails :
     - type: application
     - estimated_monthly_cost: ~$18/mois

5. [AWS] Elastic IP non attachée
   Risque     : Faible
   Confiance  : High
   Ressource  : aws.ec2.elastic_ip → eipalloc-0a1b2c3d4e5f6
   Région     : eu-west-1
   Règle      : aws.ec2.elastic_ip.unattached
   Raison     : Elastic IP non associée à aucune instance ou ENI (ancienneté : 92 jours)

6. [AWS] Ancien snapshot EBS (438 jours)
   Risque     : Faible
   Confiance  : High
   Ressource  : aws.ebs.snapshot → snap-0a1b2c3d4e5f67890
   Région     : us-west-2
   Règle      : aws.ebs.snapshot.old
   Raison     : Snapshot âgé de 438 jours sans activité récente
   Détails :
     - size_gb: 200
     - estimated_monthly_cost: ~$10/mois

--- Résumé du scan ---
Total findings : 6
Par risque :     faible: 3  moyen: 2  élevé: 1
Par confiance :  high: 5  medium: 1
Gaspillage minimum estimé : ~$480/mois
(5 findings sur 6 chiffrés)
Régions scannées : us-east-1, us-west-2, eu-west-1 (auto-détectées)
```

Pas encore de compte cloud ? `cleancloud demo` affiche un exemple de sortie sans aucun credential.

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

### Flags de scan :

| Flag | Fonction |
|---|---|
| `--provider aws\|azure\|gcp` | Fournisseur cloud à scanner *(obligatoire)* |
| `--category hygiene\|ai\|all` | Catégorie de règles : `hygiene` (défaut), `ai` (SageMaker sur AWS, AML Compute sur Azure) ou `all` (hygiene + IA) |
| `--region REGION` | Scanner une seule région |
| `--all-regions` | Toutes les régions actives — AWS/Azure uniquement |
| **AWS multi-comptes** | |
| `--org` | Auto-découverte via AWS Organizations |
| `--multi-account FILE` | Fichier de config listant les comptes |
| `--accounts 111,222` | IDs de comptes inline, séparés par des virgules |
| `--concurrency N` | Comptes/projets en parallèle (défaut : 3) |
| `--timeout SECONDS` | Timeout total du scan en secondes (défaut : 3600) |
| **Azure multi-abonnements** | |
| `--management-group ID` | Scanner tous les abonnements d'un Management Group |
| `--subscription ID` | Scanner un abonnement spécifique (défaut : tous les accessibles) |
| **GCP multi-projets** | |
| `--all-projects` | Scanner tous les projets GCP accessibles |
| `--project ID` | Scanner un projet spécifique (répétable) |
| **Sortie** | |
| `--output human\|json\|csv\|markdown` | Format de sortie (défaut : human) |
| `--output-file FILE` | Écrire la sortie dans un fichier |
| **Application** *(exit code 2 en cas de correspondance)* | |
| `--fail-on-confidence HIGH\|MEDIUM` | Échec sur les findings à ce niveau de confiance ou supérieur |
| `--fail-on-cost N` | Échec si gaspillage mensuel estimé ≥ $N |
| `--fail-on-findings` | Échec sur n'importe quel finding |

**Via pipx (recommandé pour usage local) :**
```bash
pipx install cleancloud
pipx ensurepath        # ajoute cleancloud au PATH — relancez votre shell après
cleancloud demo        # visualisez des findings sans aucun credential cloud
```

**Via Docker (Python non requis — fonctionne partout : CI/CD, jobs planifiés, serveurs) :**
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

# GCP : assurez-vous d'être connecté (gcloud auth application-default login)
cleancloud scan --provider gcp --all-projects
```

Pas sûr que vos credentials aient les bonnes permissions ? Lancez d'abord `cleancloud doctor --provider aws`, `cleancloud doctor --provider azure` ou `cleancloud doctor --provider gcp`.

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

**GCP — [Cloud Shell](https://shell.cloud.google.com) :**
```bash
pip install --upgrade --user cleancloud
export PATH="$HOME/.local/bin:$PATH"
cleancloud doctor --provider gcp    # vérifiez les permissions de votre session
cleancloud scan --provider gcp --all-projects
```

Les shells AWS et Azure s'authentifient via votre session du portail. Le GCP Cloud Shell utilise les Application Default Credentials gcloud, pré-configurées dans Cloud Shell.

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

> Généré par [CleanCloud](https://github.com/cleancloud-io/cleancloud) — scanner d'hygiène cloud lecture seule pour AWS, Azure et GCP.
```

Sauvegardez dans un fichier avec `--output-file results.md`. Sans `--output-file`, la sortie s'affiche dans stdout.

Pour des exemples de sortie complets incluant `doctor`, JSON, CSV et markdown : [`docs/example-outputs.md`](docs/example-outputs.md)

---

## Ce que CleanCloud détecte

32 règles pour AWS, Azure et GCP — conservatives, haut signal, conçues pour éviter les faux positifs en environnements IaC.

**AWS :**
- Compute : instances arrêtées 30+ jours (charges EBS continuent)
- Stockage : volumes EBS non attachés (HIGH), anciens snapshots EBS, anciennes AMIs, anciens snapshots RDS 90+ jours
- Réseau : Elastic IPs non attachées (HIGH), ENI détachées, NAT Gateways inactives, Load Balancers inactifs (HIGH)
- Plateforme : instances RDS inactives (HIGH)
- Observabilité : logs CloudWatch à rétention infinie
- Gouvernance : ressources sans tags, security groups inutilisés
- IA/ML *(opt-in : `--category ai`)* : endpoints SageMaker inactifs avec zéro invocations depuis 14+ jours — endpoints GPU flaggés risque HIGH ($500–$23K/mois)

**Azure :**
- Compute : VMs arrêtées (non désallouées) (HIGH)
- Stockage : disques managés non attachés (HIGH), anciens snapshots
- Réseau : adresses IP publiques inutilisées, Load Balancers vides (HIGH), App Gateways vides (HIGH), VNet Gateways inactives
- Plateforme : App Service Plans vides (HIGH), bases de données SQL inactives (HIGH), App Services inactifs, Container Registries inutilisés
- Gouvernance : ressources sans tags
- IA/ML *(opt-in : `--category ai`)* : clusters de calcul AML avec capacité baseline non nulle et aucune activité depuis 14+ jours — clusters GPU flaggés risque HIGH ($600–$15K/mois)

**GCP :**
- Compute : instances VM arrêtées 30+ jours (charges disque continuent) (HIGH)
- Stockage : Persistent Disks non attachés (HIGH), anciens snapshots 90+ jours
- Réseau : IPs statiques réservées — régionales et globales — en état RESERVED (HIGH)
- Plateforme : instances Cloud SQL inactives avec zéro connexion 14+ jours (HIGH)

Les règles sans marqueur de confiance sont MEDIUM — elles utilisent des heuristiques temporelles ou des signaux multiples. Commencez par `--fail-on-confidence HIGH` pour les gaspillages évidents, puis resserrez au fil de la validation par votre équipe.

**Détails complets des règles, signaux et preuves :** [`docs/rules.md`](docs/rules.md)

---

## Comment les équipes utilisent CleanCloud

Les scans se terminent avec `0` par défaut — ils reportent les findings sans jamais bloquer quoi que ce soit, sauf si vous le demandez explicitement. Trois patterns courants :

---

**Scan de gouvernance hebdomadaire** — le setup le plus courant pour les équipes platform et FinOps. Exécuté sur un planning, indépendamment des déploiements de code. Détecte le nouveau gaspillage avant qu'il ne s'accumule et applique un seuil de coût sur tous les comptes ou abonnements.

```yaml
# .github/workflows/cleancloud-weekly.yml
on:
  schedule:
    - cron: "0 9 * * 1"   # chaque lundi à 9h
```

```bash
# AWS — scan de toute l'org, alerte si le gaspillage mensuel dépasse 500$
cleancloud scan --provider aws --org --all-regions \
  --output json --output-file findings.json \
  --fail-on-cost 500

# Azure — scan de tous les abonnements sous un Management Group
cleancloud scan --provider azure --management-group <MGMT_GROUP_ID> \
  --output json --output-file findings.json \
  --fail-on-cost 500
```

La sortie JSON peut alimenter des alertes Slack, des tickets Jira ou un tableau de bord de coûts. Aucun agent, aucun SaaS — s'exécute entièrement dans votre propre infrastructure.

---

**Audit ponctuel** — exécutez depuis CloudShell ou votre terminal pour une vue immédiate à un instant T. Sans installation supplémentaire, sans configuration, findings en moins de 60 secondes. Utile avant une revue trimestrielle des coûts, une migration cloud, ou un audit de sécurité.

```bash
# AWS CloudShell — utilise votre session portail, pas d'auth supplémentaire
pip install --upgrade cleancloud
cleancloud scan --provider aws --all-regions

# Azure Cloud Shell — utilise votre session portail, pas d'auth supplémentaire
pip install --upgrade --user cleancloud && export PATH="$HOME/.local/bin:$PATH"
cleancloud scan --provider azure
```

---

**En CI/CD** — exécutez comme étape dans votre workflow de déploiement pour détecter le gaspillage évident avant qu'il ne soit livré. Utilisez les flags d'application pour bloquer ou alerter.

```bash
# AWS
cleancloud scan --provider aws --region us-east-1 \
  --fail-on-confidence HIGH   # exit 2 si gaspillage HIGH confidence détecté

# Azure
cleancloud scan --provider azure \
  --fail-on-confidence HIGH
```

---

**Seuils d'application** — les scans retournent toujours `0` sauf si vous activez l'application :

| Flag | Comportement | Code de sortie |
|------|-------------|----------------|
| *(aucun)* | Rapport uniquement, jamais d'échec | `0` |
| `--fail-on-confidence HIGH` | Échec sur les findings HIGH | `2` |
| `--fail-on-confidence MEDIUM` | Échec sur MEDIUM ou supérieur | `2` |
| `--fail-on-cost 50` | Échec si gaspillage mensuel estimé >= 50$ | `2` |
| `--fail-on-findings` | Échec sur n'importe quel finding | `2` |

Workflows GitHub Actions complets et prêts à l'emploi pour AWS (OIDC) et Azure (Workload Identity) — incluant la configuration OIDC, les politiques IAM/RBAC, et les patterns d'application :

**[Guide automatisation & CI/CD →](docs/ci.md)** · [Configuration AWS →](docs/aws.md) · [Configuration Azure →](docs/azure.md) · [Configuration GCP →](docs/gcp.md)

**Besoin d'aide avec OIDC ou les flags d'application ?** [Posez votre question dans notre discussion →](https://github.com/cleancloud-io/cleancloud/discussions/98)

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

## Scan multi-projets (GCP)

Conçu pour les équipes gérant plusieurs projets GCP. Scannez tous les projets accessibles en parallèle avec une seule identité — findings agrégés dans un rapport unique avec détail des coûts par projet.

```bash
# Scanner tous les projets accessibles (défaut)
cleancloud scan --provider gcp --all-projects

# Scanner des projets spécifiques
cleancloud scan --provider gcp --project mon-projet-123 --project autre-projet-456

# Avec filtre de région
cleancloud scan --provider gcp --all-projects --region us-central1
```

**Permissions requises (par projet) :**

| Permission | Requise pour |
|---|---|
| `compute.disks.list` | Disques persistants non attachés |
| `compute.instances.list` | Instances VM arrêtées |
| `compute.addresses.list` | IPs statiques régionales inutilisées |
| `compute.globalAddresses.list` | IPs statiques globales inutilisées |
| `compute.snapshots.list` | Anciens snapshots de disques |
| `cloudsql.instances.list` | Instances Cloud SQL inactives |
| `monitoring.timeSeries.list` | Vérification de l'activité des connexions SQL |

Toutes les permissions en lecture seule sont couvertes par quatre rôles prédéfinis : `roles/compute.viewer`, `roles/cloudsql.viewer`, `roles/monitoring.viewer`, et `roles/browser` (requis pour l'énumération des projets avec `--all-projects`). Pour CI/CD, utilisez Workload Identity Federation — voir [Configuration GCP →](docs/gcp.md).

**Fonctionnement :**

- **Application Default Credentials** — utilise la chaîne d'authentification GCP standard : `GOOGLE_APPLICATION_CREDENTIALS` → gcloud ADC → Workload Identity → service account attaché au serveur de métadonnées.
- **Auto-découverte** — avec `--all-projects`, CleanCloud énumère tous les projets ACTIFS accessibles via l'API Resource Manager. Avec `--project`, seuls les projets spécifiés sont scannés.
- **Parallèle avec isolation** — chaque projet s'exécute dans son propre thread. Un projet en échec (permission refusée, API non activée) n'affecte jamais les autres.
- **Dégradation gracieuse** — les règles échouant avec 403 sont enregistrées comme ignorées (avec la permission manquante nommée), pas comme des échecs de scan.
- **Détail des coûts par projet** — la sortie indique le gaspillage mensuel estimé par projet.

Guide complet : [Configuration GCP →](docs/gcp.md)

---

## Feuille de route

**Policy-as-code** — `cleancloud.yaml` avec packs de règles, exceptions par équipe, et seuils de coût en config — la principale demande de gouvernance FinOps pour 2025/2026

**Plus de règles IA/ML** — endpoints Vertex AI inactifs, instances de notebook SageMaker inutilisées, artefacts d'entraînement orphelins

**Plus de règles AWS** — lacunes de cycle de vie S3, Redshift inactif, fuite de coût NAT Gateway (services internes routant via NAT au lieu de VPC endpoints — S3, DynamoDB, ECR, SSM), VPC endpoints inutilisés

**Plus de règles Azure** — Azure Firewall inactif, pools de nœuds AKS inactifs, pools Azure Batch inutilisés

**Plus de règles GCP** — pools de nœuds GKE inactifs, gaspillage de slots BigQuery, stockage froid GCS, révisions Cloud Run inactives

**Filtrage de règles** — flag `--rules` pour exécuter un sous-ensemble de règles

---

## Documentation

- [`docs/rules.md`](docs/rules.md) — Règles de détection, signaux et preuves
- [`docs/aws.md`](docs/aws.md) — Politique IAM AWS et configuration OIDC
- [`docs/azure.md`](docs/azure.md) — RBAC Azure et configuration Workload Identity
- [`docs/gcp.md`](docs/gcp.md) — Permissions IAM GCP et configuration Application Default Credentials
- [`docs/ci.md`](docs/ci.md) — Automatisation, scans planifiés et intégration CI/CD
- [`docs/example-outputs.md`](docs/example-outputs.md) — Exemples de sortie complets
- [`SECURITY.md`](SECURITY.md) — Politique de sécurité et modèle de menace
- [`docs/infosec-readiness.md`](docs/infosec-readiness.md) — IAM Proof Pack, modèle de menace

---

**Vous avez trouvé un bug ?** [Ouvrez une issue](https://github.com/cleancloud-io/cleancloud/issues)

**Demande de fonctionnalité ?** [Démarrez une discussion](https://github.com/cleancloud-io/cleancloud/discussions)

**Questions ?** suresh@getcleancloud.com

[Licence MIT](LICENSE)
