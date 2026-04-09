# Policy Configuration Reference

CleanCloud is policy-as-code. Drop a `cleancloud.yaml` in your repository root and it is auto-detected on every scan. Version-control it alongside your infrastructure — every exception is a git-reviewable approval.

> **Quick links:** [Exit codes](#exit-codes) · [Filtering precedence](#filtering-precedence) · [Rule IDs](rules.md) · [CI/CD integration](ci.md) · [Real-world examples](#real-world-examples) · [Troubleshooting](troubleshooting.md)

---

## Auto-detection

CleanCloud looks for a config file in this order:

1. `--config path/to/cleancloud.yaml` (CLI flag — highest priority)
2. `cleancloud.yaml` in the current working directory
3. `.cleancloud/config.yaml` in the current working directory
4. No config — all rules enabled with default settings

---

## Filtering precedence

Filters are applied in this order (strongest first):

| Priority | Layer | What it does |
|---|---|---|
| 1 | **Exceptions** | Explicit human approvals — bypass all other filters |
| 2 | **Tag filtering** | Suppress findings on tagged/labelled resources |
| 3 | **Rule enable/disable** | Skip rules entirely before the scan runs |
| 4 | **Rule params** | Tune rule thresholds (e.g. `idle_days`) |
| 5 | **Defaults** | Global fallbacks for `min_cost`, `confidence`, `override_risk_level` |
| 6 | **Thresholds** | CI/CD exit-code policy (applied after all findings are collected) |

**Exceptions are absolute.** A resource in the exceptions list is never re-evaluated by any downstream filter (tag rules, min_cost, confidence, or thresholds). This invariant holds regardless of other config — exceptions represent human approvals, not cost policy.

---

## Full config reference

```yaml
version: 1

# ── Defaults ────────────────────────────────────────────────────────────────
# Applied to every rule unless overridden at the rule level.
defaults:
  min_cost: 10          # suppress findings below $10/month (per-finding)
  confidence: MEDIUM    # suppress LOW confidence findings globally
  # override_risk_level: HIGH  # rarely used globally; prefer per-rule

# ── Tag filtering ────────────────────────────────────────────────────────────
tag_filtering:
  enabled: true
  mode: exclude         # "exclude" suppresses findings on matched resources
  ignore:
    - key: env
      values: [production, staging]  # list of values to match
    - key: cleancloud-ignore  # key-only match (any value)

# ── Rule configuration ───────────────────────────────────────────────────────
rules:
  aws.resource.untagged:
    enabled: false

  aws.rds.instance.idle:
    enabled: true
    min_cost: 100        # suppress findings below $100/month (overrides default)
    confidence: MEDIUM   # suppress LOW confidence findings for this rule
    params:
      idle_days: 21      # flag after 21 days idle (default: 14)

  aws.sagemaker.endpoint.idle:
    override_risk_level: HIGH  # override `risk` field for display/reporting only

# ── Exceptions ────────────────────────────────────────────────────────────────
exceptions:
  - rule_id: aws.ec2.instance.stopped
    resource_id: i-0abc1234567890def
    reason: "Bastion — started on demand"

  - rule_id: aws.rds.instance.idle
    resource_id: "db-test-*"          # glob: suppresses all db-test-* resources
    reason: "Test databases are ephemeral"

  - rule_id: aws.ebs.unattached
    resource_id: "vol-*"
    account_id: "111111111111"        # narrow to a specific AWS account
    region: us-east-1                 # narrow to a specific region
    reason: "Legacy volumes in legacy account"

# ── Thresholds ─────────────────────────────────────────────────────────────────
thresholds:
  fail_on_confidence: HIGH   # exit 2 if any HIGH confidence finding remains
  fail_on_cost: 500          # exit 2 if total estimated waste >= $500/month
  fail_on_findings: false    # exit 2 on any finding (usually too noisy for CI)
```

---

## Sections

### `scan`

Execution context defaults. CLI flags always take precedence — these are fallbacks when flags are omitted, letting you run `cleancloud scan --config cleancloud.yaml` with no other flags.

```yaml
scan:
  provider: aws          # default provider (overridden by --provider)
  regions: auto          # auto-detect active regions (equivalent to --all-regions)
  # regions: us-east-1  # or pin to a single region (equivalent to --region)
```

| Field | Type | Description |
|---|---|---|
| `provider` | `aws` \| `azure` \| `gcp` | Default provider. CLI `--provider` overrides this. |
| `regions` | `"auto"` or region string | `auto` = all active regions. A string = single region. CLI `--region` / `--all-regions` override this. |

> **Note:** `scan` is execution context, not policy. It controls *where* to scan. Policy sections (`rules`, `exceptions`, `thresholds`) control *what* to evaluate.

---

### `defaults`

Global fallbacks applied to every rule unless the rule has its own setting.

| Field | Type | Description |
|---|---|---|
| `min_cost` | float | Suppress findings with `estimated_monthly_cost_usd` below this value. Per-finding. |
| `confidence` | LOW \| MEDIUM \| HIGH | Suppress findings below this confidence level. |
| `override_risk_level` | LOW \| MEDIUM \| HIGH | Override the `risk` field on all findings (display only). |

---

### `tag_filtering`

Suppress findings on resources that carry specific tags or labels.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enable/disable tag filtering. |
| `mode` | string | `"exclude"` | `"exclude"` suppresses matched resources. `"include"` (allowlist) is planned. |
| `ignore` | list | `[]` | List of `{key, values?}` tag rules. `values` accepts a list of strings to match; omit (or leave empty) to match any value (key-only match). |

**Precedence:** Tag filtering runs after exceptions. Explicitly-excepted resources are not re-suppressed by a tag rule.

---

### `rules`

Enable/disable rules, tune parameters, and override confidence/cost thresholds per rule.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Set `false` to skip this rule entirely (pre-scan). |
| `min_cost` | float | `null` | Suppress findings below this monthly cost. Overrides `defaults.min_cost`. |
| `confidence` | LOW \| MEDIUM \| HIGH | `null` | Minimum confidence to report. Overrides `defaults.confidence`. |
| `override_risk_level` | LOW \| MEDIUM \| HIGH | `null` | Override the `risk` field on findings. Display/reporting only — does not affect `fail_on_confidence`. |
| `params` | dict | `{}` | Pass named parameters to the rule function. Unknown keys or wrong types raise an error at scan start. |

**Rule IDs** must match exactly — a typo raises an error with a suggestion:
```
Unknown rule ID 'aws.rds.instnace.idle' (did you mean 'aws.rds.instance.idle'?)
```

See [rules.md](rules.md) for the full list of rule IDs and their supported params.

**Common params:**

| Param | Rule ID | Default | Description |
|---|---|---|---|
| `idle_days` | `aws.elbv2.load_balancer.idle` | 14 | Days of zero traffic before flagging |
| `idle_days` | `aws.ec2.nat_gateway.idle` | 14 | Days of zero traffic before flagging |
| `idle_days` | `aws.rds.instance.idle` | 14 | Days of no connections before flagging |
| `idle_days` | `aws.sagemaker.endpoint.idle` | 14 | Days of zero invocations before flagging |
| `idle_days` | `aws.sagemaker.notebook.idle` | 14 | Days since last control-plane activity before flagging |
| `idle_days` | `azure.aml.compute.idle` | 14 | Days of no runs before flagging |
| `idle_days` | `azure.sql.database.idle` | 14 | Days of no connections before flagging |
| `idle_days` | `azure.app_service.idle` | 14 | Days of zero requests before flagging |
| `max_age_days` | `aws.ec2.ami.old` | 180 | Age in days before flagging |
| `max_age_days` | `aws.ebs.snapshot.old` | 90 | Age in days before flagging |
| `max_age_days` | `aws.rds.snapshot.old` | 90 | Age in days before flagging |
| `max_age_days` | `aws.ec2.eni.detached` | 60 | Age in days before flagging |
| `max_age_days` | `aws.ec2.instance.stopped` | 30 | Days stopped before flagging |
| `max_age_days` | `gcp.compute.snapshot.old` | 90 | Age in days before flagging |
| `max_age_days` | `gcp.compute.vm.stopped` | 30 | Days stopped before flagging |
| `days_unattached` | `aws.ec2.elastic_ip.unattached` | 30 | Days unattached before flagging |

---

### `exceptions`

Suppress findings for specific resources. **Exceptions are absolute** — they run first in the filtering pipeline and a matched finding is never re-evaluated by any downstream filter (min_cost, confidence, tag rules, or CI thresholds). This is by design: an exception represents an explicit human approval, not a policy tuning parameter.

| Field | Type | Required | Description |
|---|---|---|---|
| `rule_id` | string | ✅ | Exact rule ID match. |
| `resource_id` | string | ✅ | Glob pattern supported: `*`, `?`, `[seq]`. E.g. `"test-*"`, `"*-staging"`. |
| `reason` | string | — | Human-readable justification. Recommended for auditability. |
| `account_id` | string | — | Narrow to a specific AWS account ID, GCP project ID, or Azure subscription ID. If omitted, matches any account. |
| `region` | string | — | Narrow to a specific region (e.g. `us-east-1`). If omitted, matches any region. |
| `expires_at` | string | — | ISO date `YYYY-MM-DD`. Exception is skipped (with a stderr warning) after this date. Prevents exception graveyard. |

**Examples:**

```yaml
exceptions:
  # Exact match
  - rule_id: aws.ec2.instance.stopped
    resource_id: i-0abc1234567890def
    reason: "Bastion host — started on demand"

  # Glob — suppress all test databases
  - rule_id: aws.rds.instance.idle
    resource_id: "db-test-*"
    reason: "Test databases are ephemeral"

  # Scoped to one account + region
  - rule_id: aws.ebs.unattached
    resource_id: "vol-*"
    account_id: "111111111111"
    region: us-west-2
    reason: "Archive volumes in legacy account"
```

---

### `categories`

Override the default scan category in config — equivalent to `--category` on the CLI. CLI flag takes precedence when explicitly set.

| Field | Type | Default | Description |
|---|---|---|---|
| `include` | list | `["hygiene"]` | Categories to run. Values: `hygiene`, `ai`, `all`. `[hygiene, ai]` is equivalent to `all`. |

**Example:**
```yaml
categories:
  include: [hygiene, ai]   # same as: cleancloud scan --category all
```

---

### `thresholds`

Config-file equivalents of `--fail-on-*` CLI flags. CLI flags take precedence when both are set.

| Field | Type | Default | Description |
|---|---|---|---|
| `fail_on_findings` | bool | `false` | Exit 2 if any findings remain after filtering. |
| `fail_on_confidence` | LOW \| MEDIUM \| HIGH | `null` | Exit 2 if any finding has confidence ≥ this level. |
| `fail_on_cost` | float | `null` | Exit 2 if total `estimated_monthly_cost_usd` across all findings ≥ this value. |

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no policy violation |
| `1` | Unexpected error (bug or infrastructure failure) |
| `2` | Policy violation — one or more threshold conditions breached |
| `3` | Permission error — insufficient IAM/RBAC permissions to complete scan |

**Threshold evaluation order** (all conditions are OR — first breach wins):

1. `fail_on_findings: true` — any remaining finding triggers exit 2
2. `fail_on_confidence: X` — any finding with confidence ≥ X triggers exit 2
3. `fail_on_cost: X` — total estimated waste ≥ X triggers exit 2

If multiple thresholds are configured, the first one that triggers determines the exit code. All conditions use OR logic — there is no AND mode.

**Important:** `override_risk_level` in rules does NOT affect `fail_on_confidence`. Thresholds evaluate signal strength (confidence), not the display risk label.

---

## Multi-account scanning

Multi-account scope is configured via CLI flags today. YAML-based scope configuration is planned.

```bash
# Scan all AWS Organization accounts
cleancloud scan --provider aws --org --all-regions --config cleancloud.yaml

# Scan specific accounts
cleancloud scan --provider aws --accounts 111111111111,222222222222 --config cleancloud.yaml
```

**Scoping exceptions to specific accounts** is one of the most powerful (and underused) features. In a 50-account org, the same resource ID prefix can exist in multiple accounts. Without `account_id`, an exception would suppress findings across all of them:

```yaml
exceptions:
  # ❌ Suppresses vol-* in ALL accounts — almost never what you want
  - rule_id: aws.ebs.unattached
    resource_id: "vol-*"
    reason: "Archive volumes"

  # ✅ Scoped to a single account + region — precise and auditable
  - rule_id: aws.ebs.unattached
    resource_id: "vol-*"
    account_id: "111111111111"   # archive account
    region: us-west-2
    reason: "Archive volumes in legacy account — migration planned Q3"

  # ✅ Suppress all test databases across a dedicated test account
  - rule_id: aws.rds.instance.idle
    resource_id: "db-*"
    account_id: "222222222222"   # test/dev account
    reason: "Dev account databases are intentionally ephemeral"
```

Rule tuning via `params` also works consistently across accounts — a single `cleancloud.yaml` at the org root applies to all accounts in the scan.

---

## Confidence vs. risk vs. override_risk_level

These three concepts are distinct:

| Concept | Field | Set by | Affects |
|---|---|---|---|
| **Confidence** | `finding.confidence` | Rule logic (signal strength) | Filtering, CI/CD thresholds, sorting |
| **Risk** | `finding.risk` | Rule logic (cost/impact estimate) | Display only |
| **override_risk_level** | config `override_risk_level` | Policy config | Overrides `finding.risk` for display — does NOT affect confidence or thresholds |

Use `thresholds.fail_on_confidence` (not `override_risk_level`) for CI/CD gates.

---

## Category filtering

Run specific rule categories via CLI:

```bash
cleancloud scan --provider aws --category hygiene   # default: infrastructure waste
cleancloud scan --provider aws --category ai        # AI/ML waste (SageMaker, AML, Vertex)
cleancloud scan --provider aws --category all       # all rules
```

YAML-based category configuration is planned.

---

## Real-world examples

### Exclude production and staging from findings

Tag your prod/staging resources with `env: production` / `env: staging` and suppress them globally:

```yaml
tag_filtering:
  enabled: true
  mode: exclude
  ignore:
    - key: env
      values: [production, staging]
    - key: cleancloud-ignore   # opt-out any resource with this tag (any value)
```

Findings on tagged resources are suppressed before thresholds are evaluated.

---

### Fail CI if monthly waste exceeds $500

```yaml
thresholds:
  fail_on_cost: 500        # exit 2 if total estimated waste >= $500/month
  fail_on_confidence: HIGH # exit 2 if any HIGH confidence finding remains
```

Run weekly in CI:
```bash
cleancloud scan --provider aws --org --all-regions --output json --output-file findings.json
```

---

### Exclude specific resources by ID (with expiry)

```yaml
exceptions:
  # Known keep-alive — reviewed quarterly
  - rule_id: aws.ec2.instance.stopped
    resource_id: i-0abc1234567890def
    reason: "Bastion host — started on demand"
    expires_at: "2026-12-31"

  # Suppress all test databases (glob)
  - rule_id: aws.rds.instance.idle
    resource_id: "db-test-*"
    reason: "Test databases are intentionally ephemeral"

  # Scope to one account + region (avoid suppressing across all accounts)
  - rule_id: aws.ebs.unattached
    resource_id: "vol-*"
    account_id: "111111111111"
    region: us-west-2
    reason: "Archive volumes — migration planned Q3"
```

---

### Multi-account org scan with per-rule tuning

```yaml
scan:
  provider: aws
  regions: auto

defaults:
  min_cost: 10           # suppress noise below $10/month
  confidence: MEDIUM     # skip LOW confidence findings

rules:
  aws.rds.instance.idle:
    min_cost: 100         # only flag RDS instances with > $100/month estimated cost
    params:
      idle_days: 21       # require 21 days idle (default: 14)

  aws.sagemaker.endpoint.idle:
    override_risk_level: HIGH   # escalate risk label for visibility in reports

  aws.sagemaker.notebook.idle:
    params:
      idle_days: 21             # flag notebooks with no activity for 21+ days (default: 14)

  aws.resource.untagged:
    enabled: false              # team manages tags separately

thresholds:
  fail_on_confidence: HIGH
  fail_on_cost: 500
```

Commit this to your repo root and run:
```bash
cleancloud scan --org --all-regions
```

---

### Separate configs per environment

Create one config per environment — pass with `--config`:

**`configs/prod.yaml`** — strict:
```yaml
defaults:
  confidence: MEDIUM
thresholds:
  fail_on_confidence: HIGH
  fail_on_cost: 200
```

**`configs/staging.yaml`** — lenient:
```yaml
defaults:
  min_cost: 50
thresholds:
  fail_on_cost: 1000
```

```bash
cleancloud scan --provider aws --config configs/prod.yaml --all-regions
cleancloud scan --provider aws --config configs/staging.yaml --region us-east-1
```

---

## Tips

**Start conservative, tighten later:**
```yaml
defaults:
  confidence: HIGH    # only surface HIGH confidence findings initially
  min_cost: 50        # ignore small findings while calibrating
```

**Silence a noisy rule without disabling it:**
```yaml
rules:
  aws.resource.untagged:
    confidence: HIGH  # only report HIGH confidence untagged findings
```

**Different thresholds for different environments:** Use separate config files per environment and pass with `--config`:
```bash
cleancloud scan --provider aws --config configs/staging.yaml
cleancloud scan --provider aws --config configs/production.yaml
```
