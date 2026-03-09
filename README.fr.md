# CleanCloud

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
[![Security Scanning](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml)
![GitHub stars](https://img.shields.io/github/stars/cleancloud-io/cleancloud?style=social)

**Languages / Langues :**
🇬🇧 [English](README.md) | 🇫🇷 [Français](README.fr.md)

---

**Trivy pour le gaspillage cloud. Un scanner qui détecte les ressources orphelines et applique l'hygiène en CI.**

Comme `tfsec` pour Terraform ou `trivy` pour les conteneurs — CleanCloud scanne votre environnement cloud et rapporte ce qui gaspille de l'argent. Exécutez-le une fois pour un audit ponctuel, planifiez-le, ou intégrez-le en CI/CD pour bloquer les builds sur des violations de politique.

- **20 règles de détection haut signal :** volumes orphelins, bases de données inactives, load balancers vides, et plus
- **Gaspillage mensuel estimé :** par finding et en agrégat
- **Application de politique CI/CD (opt-in) :** `--fail-on-confidence HIGH` ou `--fail-on-cost 100` gate votre pipeline
- **Formats de sortie multiples :** lisible, JSON, CSV, et markdown (à coller dans vos PRs GitHub ou Slack)
- **Lecture seule par conception :** aucune suppression, aucune modification de tags, aucune mutation — jamais
- **Aucun agent. Zéro télémétrie. Pas de SaaS.** S'exécute dans votre environnement, les données ne quittent jamais votre périmètre

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

## Ce qu'en disent les utilisateurs

> "Outil de découverte solide qui remonte les économies potentielles. Facile à installer et à utiliser !"
> — [Utilisateur Reddit](https://www.reddit.com/r/AZURE/comments/1rm7an5/comment/o8zfv6a/)

---

## Démarrage

```bash
pipx install cleancloud
pipx ensurepath        # ajoute cleancloud au PATH — relancez votre shell après
cleancloud demo        # visualisez des findings sans aucun credential cloud
```

Prêt à scanner votre vrai environnement :

```bash
cleancloud scan --provider aws --all-regions
cleancloud scan --provider azure
```

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

**Version minimale recommandée : v1.6.3** — les versions antérieures ont des problèmes de setup. Exécutez `cleancloud --version` pour vérifier.

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

### GitHub Actions — AWS (OIDC)

```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
    aws-region: us-east-1

- run: pip install cleancloud

- run: |
    cleancloud scan --provider aws --all-regions \
      --fail-on-confidence HIGH \
      --output json --output-file scan.json
```

### GitHub Actions — Azure (Workload Identity)

```yaml
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

- run: pip install cleancloud

- run: |
    cleancloud scan --provider azure \
      --fail-on-confidence MEDIUM \
      --output json --output-file scan.json
```

**Guide CI/CD complet :** [`docs/ci.md`](docs/ci.md) — configuration OIDC, patterns d'application, formats de sortie.
Guides de configuration : [AWS](docs/aws.md) · [Azure](docs/azure.md)

> Les snippets CI/CD ci-dessus utilisent `pip install` — correct pour les runners éphémères où l'isolation pipx n'est pas nécessaire.

---

## Feuille de route

- Règles AWS supplémentaires (cycle de vie S3, instances EC2 arrêtées)
- Policy-as-code dans `cleancloud.yaml` (`fail_on_confidence`, `fail_on_cost` en config)
- Filtrage de règles (flag `--rules`)
- Scan multi-comptes (AWS Organizations)

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
