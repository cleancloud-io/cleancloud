# CleanCloud

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

🇬🇧 [English](README.md) | 🇫🇷 Français &nbsp;·&nbsp; **Configuration :** [AWS →](docs/aws.md) · [Azure →](docs/azure.md) · [GCP →](docs/gcp.md) · [Tous les docs →](docs/rules.md)

---

**Trouvez 500–20 000 $/mois de gaspillage cloud inactif en 60 secondes — aucun credential requis :**

```bash
# Essayez instantanément (sans installation) :
docker run --rm getcleancloud/cleancloud:latest demo

# Ou installez localement :
pipx install cleancloud
cleancloud demo
```

*`scan` et `doctor` avec Docker nécessitent de monter les credentials → [Utilisation Docker →](docs/ci.md#using-the-docker-image)*

CleanCloud scanne AWS, Azure et GCP et nomme les ressources inactives spécifiques à examiner — avec le coût par ressource. **Lecture seule. Aucun agent. Pas de SaaS.**

---

## Exemple de résultat

```
cleancloud demo --category ai

3 candidats de revue trouvés :

1. [AWS] Instance EC2 GPU inactive (utilisation GPU <5% sur 7 jours)
   Risque     : Critique
   Confiance  : High
   Ressource  : aws.ec2.instance → i-0a1b2c3d4e5f67890
   Région     : us-east-1
   Règle      : aws.ec2.gpu.idle
   Raison     : Utilisation GPU 1,2% depuis 7 jours (p4d.24xlarge — ml-training-cluster-node-1)
   Détails :
     - estimated_monthly_cost: ~$23 374/mois

2. [GCP] Endpoint Vertex AI inactif (2 réplique(s) toujours active(s), zéro requête)
   Risque     : Élevé
   Confiance  : High
   Ressource  : gcp.vertex.endpoint → projects/ml-platform/locations/us-central1/endpoints/8842531067721654272
   Région     : us-central1
   Règle      : gcp.vertex.endpoint.idle
   Raison     : L'endpoint a un plancher de service provisionné de 2 réplique(s) ; la télémétrie de comptage des requêtes (couverture : complète) montre un taux maximum observé == 0 sur une fenêtre de 14j
   Détails :
     - provisioned_serving_floor: 2
     - in_scope_model_count: 1
     - has_accelerator: true
     - telemetry_coverage_state: complete

3. [Azure] Instance de calcul Azure ML inactive (31 jours sans activité)
   Risque     : Élevé
   Confiance  : High
   Ressource  : azure.ml.compute_instance → ws-prod/compute/ds-workstation-nc24
   Région     : eastus
   Règle      : azure.ml.compute_instance.idle
   Raison     : Aucune activité sur le plan de contrôle depuis 31 jours, état Running (Standard_NC24s_v3, GPU)
   Détails :
     - estimated_monthly_cost: ~$2 190/mois

4. [AWS] Instance RDS inactive (zéro connexion depuis 21 jours)
   Risque     : Élevé
   Confiance  : High
   Ressource  : aws.rds.instance → db-prod-analytics
   Région     : us-east-1
   Règle      : aws.rds.instance.idle
   Raison     : Zéro connexion depuis 21 jours (db.r5.large, postgres 15.4)
   Détails :
     - estimated_monthly_cost: ~$380/mois

--- Résumé du scan ---
Total candidats de revue : 4
Par risque :     critique: 1  élevé: 3
Gaspillage minimum estimé : ~$25 944/mois
```

*Exemple complet (10 findings) : [`docs/example-outputs.md`](docs/example-outputs.md)*

---

## Mentionné dans la presse

- [Korben](https://korben.info/cleancloud-nettoyeur-cloud-aws-azure.html) 🇫🇷 — Grand média tech français
- [Last Week in AWS #457](https://www.lastweekinaws.com/newsletter/15259/) — La newsletter AWS de Corey Quinn

> "Outil de découverte solide qui remonte les économies potentielles. Facile à installer et à utiliser !"
> — [Utilisateur Reddit](https://www.reddit.com/r/AZURE/comments/1rm7an5/comment/o8zfv6a/)

---

**CleanCloud est un scanner d'hygiène cloud — lit votre inventaire, signale les ressources inactives spécifiques comme candidats de revue, et estime le coût de leur maintien.**

- Détecte le gaspillage IA/ML coûteux : SageMaker, AML, Vertex AI — ressources GPU signalées comme candidats à risque plus élevé (500–23 000 $/mois)
- Fonctionne sur AWS, Azure et GCP en un seul outil
- S'exécute entièrement dans votre environnement — aucun agent, pas de SaaS, aucun credential stocké
- 48 règles de détection sélectives et haut signal, conçues pour éviter les faux positifs en environnements IaC
- Prêt pour CI/CD — codes de sortie d'application + sorties JSON/CSV/markdown

### Ce que CleanCloud ne fait PAS

- Aucune suppression ni modification de ressources cloud
- Aucun accès en écriture à une API cloud
- Aucun credential stocké, aucune télémétrie envoyée
- Aucun compte SaaS ni agent requis

Entièrement en lecture seule. Sûr pour la production et les environnements réglementés.

---

## Démarrage

```bash
# Ajoutez votre fournisseur cloud et scannez :
pipx install 'cleancloud[aws]'             # ou [azure], [gcp], [all]
cleancloud scan --provider aws --all-regions
cleancloud scan --provider azure
cleancloud scan --provider gcp --all-projects
```

**Choisissez votre chemin :**

| Je veux… | Par ici |
|---|---|
| Scanner AWS | [Configuration AWS (politique IAM, régions, multi-comptes) →](docs/aws.md) |
| Scanner Azure | [Configuration Azure (RBAC, abonnements, Workload Identity) →](docs/azure.md) |
| Scanner GCP | [Configuration GCP (IAM, projets, ADC) →](docs/gcp.md) |
| Utiliser en CI/CD | [Guide CI/CD (GitHub Actions, GitLab, codes de sortie) →](docs/ci.md) |
| Supprimer des findings / définir des seuils | [Référence de configuration policy-as-code →](docs/configuration.md) |
| Filtrage par tag, patterns d'exceptions, déploiement progressif | [Bonnes pratiques →](docs/best-practices.md) |
| Scanner plusieurs comptes AWS | [Configuration multi-comptes →](docs/aws.md#multi-account-scanning) |
| Résoudre une erreur | [Dépannage →](docs/troubleshooting.md) |

Pas sûr que vos credentials aient les bonnes permissions ? Lancez d'abord `cleancloud doctor --provider aws`.

---

## Détection du gaspillage IA/ML

L'infrastructure IA/ML inactive est la source de gaspillage cloud invisible à la croissance la plus rapide. Contrairement au compute ou au stockage, ces ressources facturent à plein tarif même sans aucune activité — les endpoints GPU ne passent pas à zéro.

| Ressource | Coût inactif |
|---|---|
| Bedrock Provisioned Throughput | 600 – 7 300+ $ / MU / mois |
| Endpoint SageMaker (GPU) | 500 – 23 000 $ / mois |
| Instance Notebook SageMaker (GPU) | 500 – 23 000+ $ / mois |
| Studio Apps SageMaker (KernelGateway/JupyterLab/CodeEditor) | 42 – 1 600+ $ / mois |
| Domaine SageMaker (stockage EFS inactif) | Charges EFS continues |
| Training Job SageMaker (job GPU runaway/bloqué) | 670 – 2 360+ $ / jour |
| Processing Job SageMaker (bloqué/stuck) | 670 – 2 360+ $ / jour |
| Cluster AML Compute Azure (GPU) | 600 – 15 000 $ / mois |
| Instance de calcul Azure ML (GPU) | 600 – 15 000+ $ / mois |
| Endpoint en ligne Azure ML (GPU) | 200 – 2 600+ $ / mois |
| Azure AI Search (Basic+) | 261 – 4 028+ $ / mois |
| Déploiement Azure OpenAI Provisionné (PTU) | 1 460+ $ / PTU / mois |
| Endpoint Vertex AI Online Prediction (GPU) | 449 – 23 000+ $ / mois |
| Instance Vertex AI Workbench (GPU) | 449 – 8 000+ $ / mois |
| Nœud Cloud TPU (v4/v5p) | 188 – 750+ $ / jour |
| Vertex AI Feature Store (Bigtable) | 197 – 591+ $ / mois |

CleanCloud détecte les endpoints à zéro invocation / zéro prédiction, l'activité de contrôle inactive sur les notebooks et apps managés, ainsi que les training jobs managés anormalement longs sur les 3 clouds. Les outils natifs montrent la facture — ils ne nomment pas la ressource concrète à examiner.

```bash
cleancloud scan --provider aws --category ai          # PTUs Bedrock + endpoints + notebooks + domaines + Studio apps SageMaker + training jobs + processing jobs SageMaker + EC2 GPU
cleancloud scan --provider azure --category ai        # clusters AML + instances ML + endpoints en ligne + AI Search + PTUs OpenAI
cleancloud scan --provider gcp --category ai          # endpoints Vertex AI + Workbench + training jobs + Cloud TPU + Feature Stores
cleancloud scan --provider aws --category all         # hygiène + IA/ML ensemble
```

Aucune configuration supplémentaire requise — opt-in avec `--category ai`. Compatible avec les scans multi-comptes et multi-projets :

```bash
cleancloud scan --provider aws --org --all-regions --category all
```

**[Règles IA/ML →](docs/rules.md)**

---

## À qui s'adresse CleanCloud

- **Équipes platform et FinOps** — scans d'hygiène hebdomadaires sur votre AWS Org ou tenant Azure, application de seuils de gaspillage, détection de la dérive avant qu'elle ne s'accumule
- **Industries réglementées** — services financiers, santé et gouvernement qui ne peuvent pas envoyer les données de compte cloud à un fournisseur SaaS
- **Équipes mid-market** — trop grandes pour ignorer le gaspillage cloud, trop légères pour des plateformes FinOps enterprise. Les outils natifs montrent les factures ; CleanCloud montre ce qu'il faut examiner
- **Consultants cloud et MSPs** — audit d'un compte client en quelques minutes, export des findings en markdown ou JSON
- **Audits ponctuels** — exécutez dans CloudShell, findings visibles en 60 secondes, sans installation requise
- **Rapports pré-revue** — exportez les findings en markdown avant une revue trimestrielle des coûts ou un board meeting

---

## Gouvernance as Code

Déposez un `cleancloud.yaml` à la racine de votre repo. Chaque exception est une approbation auditée dans git — versionnée aux côtés de votre infrastructure.

```yaml
# cleancloud.yaml
defaults:
  confidence: MEDIUM    # ignorer les findings à faible signal
  min_cost: 10          # ignorer les findings en dessous de 10$/mois

exceptions:
  - rule_id: aws.ec2.instance.stopped
    resource_id: i-0abc1234567890def
    reason: "Bastion host — démarré à la demande"
    expires_at: "2026-12-31"          # expiration automatique — forçage de révision

  - rule_id: aws.rds.instance.idle
    resource_id: "db-test-*"          # glob — supprime toutes les bases de test
    reason: "Les bases de test sont intentionnellement éphémères"

thresholds:
  fail_on_confidence: HIGH            # exit 2 en CI si un finding HIGH confidence reste
  fail_on_cost: 500                   # exit 2 si le gaspillage total dépasse 500$/mois
```

Appliquer en CI/CD :

```bash
cleancloud scan --provider aws --org --all-regions   # détecte cleancloud.yaml automatiquement
```

**[Référence complète de configuration →](docs/configuration.md)** · [Bonnes pratiques →](docs/best-practices.md)

---

## En CI/CD

Les scans retournent `0` par défaut — les findings sont reportés, rien n'est bloqué sauf si vous le demandez.

```bash
# Gouvernance hebdomadaire : échec si le gaspillage mensuel dépasse 500$
cleancloud scan --provider aws --org --all-regions \
  --output json --output-file findings.json \
  --fail-on-cost 500

# Gate pré-déploiement : bloquer sur le gaspillage HIGH confidence
cleancloud scan --provider aws --region us-east-1 \
  --fail-on-confidence HIGH
```

| Code de sortie | Signification |
|----------------|---------------|
| `0` | Aucune violation (ou aucun flag d'application défini) |
| `1` | Erreur de configuration ou échec inattendu |
| `2` | Violation de politique — seuil dépassé |
| `3` | Credentials manquants ou permissions insuffisantes |

**[Guide CI/CD complet →](docs/ci.md)** · [AWS →](docs/aws.md) · [Azure →](docs/azure.md) · [GCP →](docs/gcp.md)

---

| | Outils natifs AWS/Azure/GCP | Plateformes FinOps SaaS | **CleanCloud** |
|---|:---:|:---:|:---:|
| Affiche les tendances de coûts | ✅ | ✅ | — |
| Nomme les ressources spécifiques à examiner | ❌ | partiel | ✅ |
| Estimation de coût déterministe par ressource | ❌ | ❌ | ✅ |
| Détecte le gaspillage IA/ML (SageMaker, AML, Vertex AI — dont les endpoints GPU) | ❌ | ❌ | ✅ |
| **Policy-as-code (exceptions + seuils dans git)** | ❌ | ❌ | ✅ |
| **Approbations d'exceptions auditées dans git** | ❌ | ❌ | ✅ |
| Lecture seule, aucun agent | ✅ | ❌ | ✅ |
| Fonctionne en environnements air-gapped / réglementés | ❌ | ❌ | ✅ |
| Aucun compte SaaS ni accès vendor requis | ❌ | ❌ | ✅ |
| Hygiène multi-comptes / multi-abonnements / multi-projets | ❌ | ✅ | ✅ |
| Application planifiée et CI/CD (codes de sortie) | ❌ | ❌ | ✅ |

---

<details>
<summary>Scan multi-comptes (AWS)</summary>

Conçu pour les entreprises utilisant AWS Organizations. Scannez chaque compte en parallèle — les findings sont agrégés dans un seul rapport.

```bash
# Scan depuis un fichier de configuration
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
| Comptes spoke | 16 permissions lecture seule (identique au scan mono-compte) |

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

**Fonctionnement :**

- **Hub-and-spoke** — CleanCloud assume `CleanCloudReadOnlyRole` dans chaque compte cible via STS. Aucun accès persistant, aucun credential stocké.
- **Trois modes de découverte** — `.cleancloud/accounts.yaml` pour un contrôle explicite, `--accounts` pour des scans ad-hoc rapides, `--org` pour l'auto-découverte complète via AWS Organizations.
- **Détection de régions efficace** — les régions actives sont découvertes une seule fois sur le compte hub et réutilisées sur tous les spokes.
- **Parallèle avec isolation** — chaque compte s'exécute dans son propre thread. Un compte en échec n'affecte jamais les autres.
- **Visibilité partielle** — si 2 régions échouent et 7 réussissent dans un compte, le compte est marqué `partial` avec les régions en échec nommées.
- **Progression en temps réel** — `[3/50] done production (123456789012) — 47s, 12 findings` affiché au fil des comptes.
- **Détail des coûts par compte** — la sortie JSON inclut le gaspillage mensuel estimé par compte.

Guide complet (politique IAM, trust policy, templates IaC) : [Configuration multi-comptes AWS →](docs/aws.md#multi-account-scanning)

</details>

<details>
<summary>Scan multi-abonnements (Azure)</summary>

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

- **Modèle d'identité plat** — un seul service principal, Reader au niveau du Management Group. Pas de complexité hub-and-spoke.
- **Trois modes de découverte** — tous les accessibles (défaut), `--management-group` pour l'auto-découverte, `--subscription` pour un contrôle explicite.
- **Parallèle avec isolation** — chaque abonnement s'exécute dans son propre thread. Un abonnement en échec n'affecte jamais les autres.
- **Gestion gracieuse des permissions** — les règles échouant avec 403 sont signalées comme ignorées (avec la permission manquante nommée), pas comme des échecs de scan.
- **Détail des coûts par abonnement** — la sortie indique le gaspillage mensuel estimé par abonnement.

Guide complet (RBAC, Workload Identity, Management Group) : [Configuration multi-abonnements Azure →](docs/azure.md#multi-subscription-scanning)

</details>

<details>
<summary>Scan multi-projets (GCP)</summary>

Conçu pour les équipes gérant plusieurs projets GCP. Scannez tous les projets accessibles en parallèle avec une seule identité — findings agrégés dans un rapport unique avec détail des coûts par projet.

```bash
# Scanner tous les projets accessibles (défaut)
cleancloud scan --provider gcp --all-projects

# Scanner des projets spécifiques
cleancloud scan --provider gcp --project mon-projet-123 --project autre-projet-456
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

Toutes les permissions en lecture seule sont couvertes par quatre rôles prédéfinis : `roles/compute.viewer`, `roles/cloudsql.viewer`, `roles/monitoring.viewer`, et `roles/browser`. Pour CI/CD, utilisez Workload Identity Federation — voir [Configuration GCP →](docs/gcp.md).

Guide complet : [Configuration GCP →](docs/gcp.md)

</details>

---

## FAQ

**Est-il sûr de l'exécuter en production ?**
Oui. CleanCloud est en lecture seule — il n'appelle que les APIs `List`, `Describe` et `Get`. Aucune écriture, aucune suppression, aucune modification de votre compte cloud.

**CleanCloud envoie-t-il mes données quelque part ?**
Non. Il s'exécute entièrement dans votre environnement. Aucune télémétrie, pas de SaaS, aucune connexion sortante sauf vers les APIs de votre cloud provider.

**Signalera-t-il des ressources gérées par Terraform / CDK ?**
CleanCloud détecte un état réellement inactif (zéro connexion, zéro trafic, zéro invocation) — pas l'existence d'une ressource. Une instance RDS gérée par Terraform avec zéro connexion depuis 30 jours sera quand même signalée. Utilisez le filtrage par tag ou les exceptions pour supprimer les ressources intentionnelles.

**Comment supprimer une ressource spécifique ?**
Deux options : taguez-la avec `cleancloud-ignore: true` (filtrage par tag), ou ajoutez une exception explicite dans `cleancloud.yaml` (policy-as-code). Les exceptions supportent les patterns glob et les dates d'expiration. Voir [Configuration policy-as-code →](docs/configuration.md#exceptions).

**Mon CI échoue sur des findings qui ne m'intéressent pas. Comment corriger ?**
Ne désactivez pas l'application — supprimez le bruit spécifique. Utilisez `min_cost` pour ignorer les findings bon marché, `confidence: MEDIUM` pour ignorer ceux à faible signal, ou ajoutez des exceptions pour les ressources intentionnelles. Voir [Dépannage →](docs/troubleshooting.md).

**Puis-je l'utiliser sans `cleancloud.yaml` ?**
Oui. Sans fichier de config, toutes les règles sont activées avec leurs valeurs par défaut. La config est optionnelle — vous pouvez démarrer avec un simple flag CLI et ajouter une config plus tard.

**Fonctionne-t-il dans des environnements air-gapped / privés ?**
Oui. CleanCloud n'a besoin d'accès réseau qu'aux endpoints API de votre cloud provider. Aucune dépendance externe, aucun téléchargement de paquets lors du scan.

---

## Ce que CleanCloud détecte

48 règles pour AWS, Azure et GCP — conservatrices, haut signal, conçues pour éviter les faux positifs en environnements IaC.

**AWS :**
- Compute : instances arrêtées 30+ jours (charges EBS continuent)
- Stockage : volumes EBS non attachés (HIGH), anciens snapshots EBS, anciennes AMIs, anciens snapshots RDS 90+ jours
- Réseau : Elastic IPs non attachées (HIGH), ENI détachées, NAT Gateways inactives, Load Balancers inactifs (HIGH)
- Plateforme : instances RDS inactives (HIGH)
- Observabilité : logs CloudWatch à rétention infinie
- Gouvernance : ressources sans tags, security groups inutilisés
- IA/ML *(opt-in : `--category ai`)* : Bedrock Provisioned Throughput (Model Units) inactifs avec zéro invocation depuis 7+ jours ; endpoints SageMaker sans trafic `InvokeEndpoint` observé depuis 14+ jours ; instances Notebook SageMaker avec timestamps de contrôle inactifs depuis 14+ jours ; Domaines SageMaker sans apps en cours d'exécution sur tous les profils et espaces depuis 30+ jours (coût de stockage EFS continu) ; Studio Apps SageMaker (`KernelGateway`/`JupyterLab`/`CodeEditor`) sans signal d'activité récent exploitable depuis 7+ jours ; training jobs SageMaker toujours `InProgress` au-delà du seuil de 24h ; processing jobs SageMaker toujours `InProgress` au-delà du seuil de 24h

**Azure :**
- Compute : VMs arrêtées (non désallouées) (HIGH)
- Stockage : disques managés non attachés (HIGH), anciens snapshots
- Réseau : adresses IP publiques inutilisées, Load Balancers vides (HIGH), App Gateways vides (HIGH), VNet Gateways inactives
- Plateforme : App Service Plans vides (HIGH), bases de données SQL inactives (HIGH), App Services inactifs, Container Registries inutilisés
- Gouvernance : ressources sans tags
- IA/ML *(opt-in : `--category ai`)* : clusters de calcul AML avec capacité baseline non nulle et aucune activité depuis 14+ jours — clusters GPU flaggés risque HIGH ($600–$15K/mois) ; instances de calcul Azure ML Running sans activité depuis 14+ jours — instances GPU flaggées risque CRITICAL ($600–$15K+/mois) ; endpoints en ligne ML managés sans requête de scoring depuis 7+ jours — endpoints GPU flaggés HIGH/CRITICAL (200–2 600+$/mois) ; services AI Search (Basic+) sans requête depuis 90+ jours — facturés par SKU × réplicas × partitions (261–4 028+$/mois) ; déploiements Azure OpenAI provisionnés (PTUs) sans requête API depuis 7+ jours — facturés ~1 460 $/PTU/mois en on-demand quel que soit le trafic

**GCP :**
- Compute : instances VM arrêtées 30+ jours (charges disque continuent) (HIGH)
- Stockage : Persistent Disks non attachés (HIGH), anciens snapshots 90+ jours
- Réseau : IPs statiques réservées — régionales et globales — en état RESERVED (HIGH)
- Plateforme : instances Cloud SQL inactives avec zéro connexion 14+ jours (HIGH)
- IA/ML *(opt-in : `--category ai`)* : endpoints Vertex AI Online Prediction inactifs avec zéro prédiction observée depuis 14+ jours (les nœuds dédiés continuent de facturer quel que soit le trafic) — endpoints GPU flaggés risque HIGH ($449–$23K+/mois) ; instances Workbench sans activité depuis 14+ jours — instances GPU flaggées HIGH/CRITICAL ($449–$8K+/mois) ; training jobs Vertex AI (CustomJobs + TrainingPipelines) dépassant 24h — risque CRITICAL pour les jobs GPU/accélérateur à 3× le seuil ; nœuds Cloud TPU (v2–v6e) en état READY avec duty_cycle quasi-nul depuis 7+ jours — un v4 inactif coûte $12,88/h, un v5p-8 coûte $33,60/h ; Feature Stores Vertex AI avec zéro requête ReadFeatureValues depuis 30+ jours — les stores Bigtable facturent ~$197/nœud/mois quelle que soit l'activité

Les règles sans marqueur de confiance sont MEDIUM — elles utilisent des heuristiques temporelles ou des signaux multiples. Commencez par `--fail-on-confidence HIGH` pour les gaspillages évidents, puis resserrez au fil de la validation par votre équipe.

**Détails complets des règles, signaux et preuves :** [`docs/rules.md`](docs/rules.md)

---

## Feuille de route

**Plus de règles IA/ML** — artefacts d'entraînement orphelins dans S3

**Plus de règles AWS** — lacunes de cycle de vie S3, Redshift inactif, fuite de coût NAT Gateway, VPC endpoints inutilisés

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
- [`docs/configuration.md`](docs/configuration.md) — Policy-as-code : exceptions, seuils, filtrage par tag
- [`docs/best-practices.md`](docs/best-practices.md) — Stratégie de déploiement, filtrage par tag, patterns d'exceptions
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — Erreurs courantes et solutions
- [`docs/example-outputs.md`](docs/example-outputs.md) — Exemples de sortie complets
- [`SECURITY.md`](SECURITY.md) — Politique de sécurité et modèle de menace
- [`docs/infosec-readiness.md`](docs/infosec-readiness.md) — IAM Proof Pack, modèle de menace

---

**Vous avez trouvé un bug ?** [Ouvrez une issue](https://github.com/cleancloud-io/cleancloud/issues)

**Demande de fonctionnalité ?** [Démarrez une discussion](https://github.com/cleancloud-io/cleancloud/discussions)

**Questions ?** suresh@getcleancloud.com

[Licence MIT](LICENSE)
