# Best Practices

Patterns for teams running CleanCloud in production — from initial rollout to org-wide enforcement.

> **Quick links:** [Tag filtering patterns](#tag-filtering) · [Exception patterns](#exception-patterns) · [Rollout strategy](#rollout-strategy) · [CI/CD enforcement](#cicd-enforcement)

---

## Rollout strategy

### Start conservative, tighten over time

Don't enable everything on day one. The goal is to build team trust in the findings before gating CI.

**Week 1 — discover:**
```yaml
# cleancloud.yaml
defaults:
  confidence: HIGH   # surface only the most obvious waste
  min_cost: 50       # ignore findings below $50/month
```
Run manually. Review findings with your team. This surfaces the highest-value, highest-signal waste with minimal noise.

**Week 2-3 — suppress known noise:**
```yaml
defaults:
  confidence: MEDIUM
  min_cost: 10
tag_filtering:
  enabled: true
  ignore:
    - key: env
      values: [production, staging]
exceptions:
  - rule_id: aws.ec2.instance.stopped
    resource_id: i-0abc1234567890def
    reason: "Bastion host — started on demand"
    expires_at: "2026-12-31"
```
Add exceptions and tag rules for resources you know are intentional.

**Week 4+ — enforce in CI:**
```yaml
thresholds:
  fail_on_confidence: HIGH
  fail_on_cost: 500
```
Now CI fails only on findings your team has already validated as real waste.

---

## Tag filtering

Tag filtering is the most scalable way to suppress noise across many resources without maintaining a long exception list.

### Exclude by environment

Tag your infrastructure with `env: production` / `env: staging` and suppress findings globally:

```yaml
tag_filtering:
  enabled: true
  mode: exclude
  ignore:
    - key: env
      values: [production, staging]
```

Findings on tagged resources are suppressed before thresholds are evaluated — they don't count toward `fail_on_cost`.

### Opt-out any resource

Add a `cleancloud-ignore` tag (any value) to suppress individual resources without touching the config:

```yaml
tag_filtering:
  ignore:
    - key: cleancloud-ignore   # key-only match — any value
```

Then tag the resource:
```bash
aws ec2 create-tags --resources i-0abc123 --tags Key=cleancloud-ignore,Value=true
```

This is useful for resources owned by other teams that you can't easily add exceptions for.

### What tag filtering does NOT do

- Tag filtering runs **after** exceptions. Excepted resources are never re-suppressed.
- Tag filtering runs **before** thresholds. Suppressed findings don't trigger `fail_on_cost` or `fail_on_confidence`.
- Tag filtering does not affect which rules run — use `rules.rule-id.enabled: false` to skip a rule entirely.

---

## Exception patterns

### Always include a reason

```yaml
exceptions:
  # ✅ auditable
  - rule_id: aws.ec2.instance.stopped
    resource_id: i-0abc1234567890def
    reason: "Bastion host — started on demand by platform team"
    expires_at: "2026-12-31"

  # ❌ no context — why? who approved? when does this change?
  - rule_id: aws.ec2.instance.stopped
    resource_id: i-0abc1234567890def
```

### Always add expiry dates

Exceptions without expiry dates accumulate into a graveyard. Add `expires_at` to force periodic review:

```yaml
exceptions:
  - rule_id: aws.rds.instance.idle
    resource_id: db-prod-reporting
    reason: "Quarterly reporting DB — idle between cycles"
    expires_at: "2026-09-30"   # reviewed quarterly
```

CleanCloud warns on stderr when an exception has expired — it doesn't silently continue to suppress.

### Scope multi-account exceptions precisely

In a multi-account org, the same resource ID prefix can exist in many accounts. Without `account_id`, an exception suppresses across all of them:

```yaml
exceptions:
  # ❌ suppresses vol-* in ALL accounts
  - rule_id: aws.ebs.unattached
    resource_id: "vol-*"
    reason: "Archive volumes"

  # ✅ scoped to the archive account only
  - rule_id: aws.ebs.unattached
    resource_id: "vol-*"
    account_id: "111111111111"
    region: us-west-2
    reason: "Archive volumes in legacy account — migration planned Q3 2026"
    expires_at: "2026-09-30"
```

### Use globs for families of resources

```yaml
exceptions:
  # suppress all test databases
  - rule_id: aws.rds.instance.idle
    resource_id: "db-test-*"
    reason: "Test databases are intentionally ephemeral"

  # suppress all dev account resources
  - rule_id: aws.ec2.instance.stopped
    resource_id: "*"
    account_id: "222222222222"
    reason: "Dev account — instances started on demand"
```

---

## CI/CD enforcement

### Use `fail_on_confidence`, not `fail_on_findings`

`fail_on_findings: true` blocks CI on every finding — including LOW confidence, low-cost findings. It's almost always too noisy. Start with confidence gating:

```yaml
thresholds:
  fail_on_confidence: HIGH    # block on obvious, high-signal waste only
  fail_on_cost: 500           # also block if total waste exceeds $500/month
  fail_on_findings: false     # don't block on every finding
```

### Don't gate pre-deploy — gate on a schedule

A pre-deploy gate that fires on cloud waste will block deploys for reasons unrelated to the current PR. Use a scheduled scan instead:

```yaml
# .github/workflows/cleancloud.yml
on:
  schedule:
    - cron: '0 9 * * 1'   # every Monday at 09:00 UTC
```

Save pre-deploy gates for specific, high-value rules (e.g. "did this PR add a new SageMaker endpoint that's already idle?").

### Separate configs per environment

One config per environment — use `--config` to select:

```bash
# strict in prod
cleancloud scan --provider aws --org --all-regions --config configs/prod.yaml

# lenient in dev
cleancloud scan --provider aws --region us-east-1 --config configs/dev.yaml
```

**`configs/prod.yaml`:**
```yaml
defaults:
  confidence: MEDIUM
  min_cost: 10
thresholds:
  fail_on_confidence: HIGH
  fail_on_cost: 200
```

**`configs/dev.yaml`:**
```yaml
defaults:
  min_cost: 50
thresholds:
  fail_on_cost: 2000
  fail_on_findings: false
```

### Store the config at the repo root

`cleancloud.yaml` in the repo root is auto-detected — no `--config` flag needed for the common case:

```bash
cleancloud scan --provider aws --all-regions   # picks up cleancloud.yaml automatically
```

This makes the scan command in CI simpler and lets developers run the same scan locally.

---

## Multi-account orgs

### One config for all accounts

A single `cleancloud.yaml` at the org repo root applies to all accounts in the scan. You don't need per-account configs:

```bash
cleancloud scan --provider aws --org --all-regions
```

### Scope exceptions to the right account

See [Exception patterns → scope multi-account exceptions precisely](#scope-multi-account-exceptions-precisely).

### Start with `--concurrency 3`, raise if stable

Default concurrency is 5. In large orgs (50+ accounts), start lower and raise once you've confirmed all spoke roles are configured correctly:

```bash
cleancloud scan --provider aws --org --all-regions --concurrency 10
```

---

## Rule tuning

### Prefer `min_cost` over `enabled: false`

Disabling a rule means you'll miss expensive instances of it. Use `min_cost` to suppress cheap findings while keeping expensive ones visible:

```yaml
rules:
  aws.rds.instance.idle:
    min_cost: 100   # only flag RDS instances with > $100/month estimated cost
    # don't set enabled: false — you'd miss a $5,000/month idle instance
```

### Tune `idle_days` for your team's workflow

Default `idle_days` is 14 for most rules. If your team regularly has 3-week sprints with resources that go idle between cycles, raise it:

```yaml
rules:
  aws.rds.instance.idle:
    params:
      idle_days: 21

  gcp.sql.instance.idle:
    params:
      idle_days: 21
```

### Use `override_risk_level` for reporting, not enforcement

`override_risk_level` changes how a finding is displayed in reports — it does NOT affect `fail_on_confidence` thresholds. Use it to escalate visibility in dashboards, not to gate CI:

```yaml
rules:
  aws.sagemaker.endpoint.idle:
    override_risk_level: HIGH   # shows as HIGH risk in reports
    # fail_on_confidence still uses the rule's real confidence signal
```

---

## See also

- [Policy config reference →](configuration.md) — full schema documentation
- [Troubleshooting →](troubleshooting.md) — common errors and fixes
- [CI/CD guide →](ci.md) — platform-specific integration examples
- [Rules reference →](rules.md) — all rule IDs, signals, and params
