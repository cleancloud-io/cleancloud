# Troubleshooting

Quick answers to common errors. Jump to your error:

- [Error: Must specify either --region or --all-regions for AWS](#error-must-specify-either---region-or---all-regions-for-aws)
- [Error: --provider is required](#error---provider-is-required)
- [Permission error / exit code 3](#permission-error--exit-code-3)
- [Error parsing cleancloud.yaml](#error-parsing-cleanclouodyaml)
- [Unknown config fields / rule ID typo](#unknown-config-fields--rule-id-typo)
- [scan.regions must be 'auto' or a list](#scanregions-must-be-auto-or-a-list)
- [findings appear even though I added an exception](#findings-appear-even-though-i-added-an-exception)
- [CI exits 2 even though findings look suppressed](#ci-exits-2-even-though-findings-look-suppressed)
- [cleancloud doctor says credentials missing](#cleancloud-doctor-says-credentials-missing)
- [zero findings but I know resources are idle](#zero-findings-but-i-know-resources-are-idle)
- [scan is very slow](#scan-is-very-slow)

---

## Error: Must specify either --region or --all-regions for AWS

```
Error: Must specify either --region or --all-regions for AWS.
```

**Cause:** AWS scans require a region scope. Unlike Azure/GCP, AWS APIs are regional and CleanCloud won't guess.

**Fix — scan all active regions:**
```bash
cleancloud scan --provider aws --all-regions
```

**Fix — scan one region:**
```bash
cleancloud scan --provider aws --region us-east-1
```

**Fix — set a default in config** (so you can run `cleancloud scan` with no flags):
```yaml
# cleancloud.yaml
scan:
  provider: aws
  regions: auto   # equivalent to --all-regions
```

---

## Error: --provider is required

```
Error: --provider is required (or set scan.provider in cleancloud.yaml)
```

**Fix — pass it on the command line:**
```bash
cleancloud scan --provider aws --all-regions
```

**Fix — set a default in config:**
```yaml
# cleancloud.yaml
scan:
  provider: aws
```

---

## Permission error / exit code 3

```
Permission error: ...
```
or exit code `3`.

**What it means:** CleanCloud ran but couldn't complete the scan due to missing IAM/RBAC permissions.

**Fix — check what's missing:**
```bash
cleancloud doctor --provider aws
cleancloud doctor --provider azure
cleancloud doctor --provider gcp
```

Doctor lists every permission checked and highlights the ones that are missing. It also prints the IAM policy you can paste directly into AWS, Azure, or GCP.

**Docs:**
- [AWS IAM policy →](aws.md)
- [Azure RBAC →](azure.md)
- [GCP permissions →](gcp.md)

---

## Error parsing cleancloud.yaml

```
Error parsing cleancloud.yaml: ...
```

**Cause:** The file has invalid YAML syntax (tabs instead of spaces, missing quotes, wrong indentation).

**Fix:** Run the file through a YAML linter:
```bash
python3 -c "import yaml; yaml.safe_load(open('cleancloud.yaml'))" && echo "OK"
```

Common mistakes:

| Wrong | Right |
|---|---|
| Indented with tabs | Use 2 spaces |
| `reason: Bastion — started on demand` | `reason: "Bastion — started on demand"` (quote strings with special chars) |
| `expires_at: 2026-12-31` | `expires_at: "2026-12-31"` (quote dates) |

---

## Unknown config fields / rule ID typo

```
Error in cleancloud.yaml: Unknown config fields: {'rulez'}
```
or
```
Unknown rule ID 'aws.rds.instnace.idle' (did you mean 'aws.rds.instance.idle'?)
```

**Fix:** Check the exact spelling. Rule IDs must match exactly — use the suggestion in the error message or see [`docs/rules.md`](rules.md) for the full list.

Top-level config sections: `version`, `scan`, `defaults`, `tag_filtering`, `rules`, `exceptions`, `categories`, `thresholds`.

---

## scan.regions must be 'auto' or a list

```
Error in cleancloud.yaml: scan.regions string value must be 'auto'. For a specific region use a list: regions: [us-east-1]
```

**Cause:** A bare region string like `regions: us-east-1` is ambiguous (is it a region name or a config token?).

**Fix:**
```yaml
# scan all active regions
scan:
  regions: auto

# pin to one region — use a list
scan:
  regions: [us-east-1]

# pin to multiple regions — not yet supported; use auto
scan:
  regions: auto
```

---

## findings appear even though I added an exception

**Check 1 — rule_id and resource_id must match exactly:**
```yaml
exceptions:
  - rule_id: aws.rds.instance.idle   # must be exact rule ID
    resource_id: db-prod-reporting   # exact resource name, or glob like "db-prod-*"
```

**Check 2 — run with `--explain` to see which filter suppressed (or didn't suppress) each finding:**
```bash
cleancloud scan --provider aws --all-regions --explain
```

**Check 3 — glob syntax:** `*` matches any sequence of characters, `?` matches one. Use quotes in YAML:
```yaml
resource_id: "db-test-*"
```

**Check 4 — account/region scope:** If `account_id` or `region` is set on the exception, it only matches resources in that account/region. Remove or adjust if you want a broader match.

**Check 5 — expired exception:** If `expires_at` is set and the date has passed, the exception is skipped with a warning. Check stderr output.

---

## CI exits 2 even though findings look suppressed

Exit code `2` means a threshold was breached — check `thresholds` in your config or `--fail-on-*` flags.

**Check what threshold fired:**
```bash
cleancloud scan --provider aws --all-regions --explain 2>&1 | tail -20
```

**Common causes:**

| Symptom | Fix |
|---|---|
| `fail_on_confidence: HIGH` and there are HIGH findings | Suppress the finding (exception, tag, min_cost) or raise the threshold |
| `fail_on_cost: 500` and total waste > $500 | Suppress expensive findings or raise the threshold |
| `fail_on_findings: true` and there are any findings | Switch to `fail_on_confidence` or `fail_on_cost` for less noise |

**Note:** `override_risk_level` does NOT affect `fail_on_confidence`. Thresholds evaluate signal strength (confidence), not the display risk label.

---

## cleancloud doctor says credentials missing

```
✗ AWS credentials not found
```

**AWS:**
```bash
# Check which profile/credentials are active
aws sts get-caller-identity

# If using a named profile
cleancloud doctor --provider aws --profile my-profile
cleancloud scan --provider aws --all-regions --profile my-profile
```

**Azure:**
```bash
# Interactive login (for local use)
az login

# Check active account
az account show
```

**GCP:**
```bash
# Application Default Credentials (ADC) — standard for local + CI
gcloud auth application-default login

# Check active credentials
gcloud auth list
```

For CI/CD, use service accounts / OIDC instead of interactive login. See [CI/CD guide →](ci.md).

---

## zero findings but I know resources are idle

**Check 1 — are findings suppressed by min_cost?**

Default `cleancloud.yaml` sets `defaults.min_cost: 5`. Resources below $5/month are suppressed. Lower or remove it:

```yaml
defaults:
  min_cost: 0   # show all findings regardless of cost
```

**Check 2 — are findings suppressed by confidence?**

Default sets `defaults.confidence: MEDIUM`. LOW confidence findings are hidden. Lower it to see them:

```yaml
defaults:
  confidence: LOW
```

**Check 3 — are findings suppressed by tag filtering?**
```yaml
tag_filtering:
  enabled: false   # temporarily disable to test
```

**Check 4 — are you scanning the right regions?**
```bash
cleancloud scan --provider aws --all-regions   # not just --region us-east-1
```

**Check 5 — is the rule disabled?**
```yaml
rules:
  aws.rds.instance.idle:
    enabled: false   # is this set?
```

---

## scan is very slow

**AWS:**
- Region detection runs in parallel. `--all-regions` is usually fast; if slow, pin to active regions.
- Multi-account scans: increase concurrency with `--concurrency 10` (default: 5).

**Azure / GCP:**
- Subscriptions/projects are scanned in parallel. Slow scans usually mean a permission error on one resource type causing a timeout — check stderr for warnings.

**Large output:**
- Use `--output json --output-file findings.json` to write directly to a file instead of stdout.

---

## Still stuck?

- Run `cleancloud doctor --provider <aws|azure|gcp>` — it diagnoses credentials, permissions, and config in one command.
- Open an issue: [github.com/cleancloud-io/cleancloud/issues](https://github.com/cleancloud-io/cleancloud/issues)
- Email: suresh@getcleancloud.com
