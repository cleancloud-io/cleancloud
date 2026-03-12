# Confidence Levels in CleanCloud

CleanCloud assigns an explicit confidence level to every finding:
**LOW**, **MEDIUM**, or **HIGH**.

Confidence represents **how safe it is to review a resource as potentially abandoned** —
not how much money it might save, and not a recommendation to delete anything.

## Why Confidence Exists

Cloud waste detection is inherently ambiguous. A detached disk might be orphaned — or it might be waiting for a scheduled reattachment. An untagged resource might be waste — or it might predate the tagging policy.

Confidence levels allow CleanCloud to surface candidates without overstepping. Rather than binary "waste / not waste" judgements, CleanCloud assigns a confidence that reflects the strength of observable evidence, so teams can decide what to act on — and when.

## What Confidence Means

Confidence answers one question only:

> “How likely is this resource to be genuinely orphaned or inactive,
based on conservative, observable signals?”

It does **not** mean:
- Safe to delete
- Unused forever
- Not referenced by code
- Not required for disaster recovery


## Confidence Levels

| Level | Meaning |
|------|--------|
| LOW | Weak or partial signals. Resource may still be legitimate or newly created. |
| MEDIUM | Multiple signals suggest inactivity, but uncertainty remains. |
| HIGH | Strong, long-lived signals consistently indicate abandonment. |

HIGH confidence requires strong, deterministic signals — either multiple corroborating signals or a single binary state check (e.g., a resource with zero associations is definitively unattached).

## Signals Used

Depending on the rule, CleanCloud may evaluate:

- Resource age
- Attachment state
- Last activity timestamp
- Absence of recent writes or ingestion
- Missing ownership or lifecycle tags
- Cross-checks against related resources

Signals are:
- Read-only
- Deterministic
- Cloud-provider native

Signals flow through a simple pipeline:

```
Observable Signals  →  Rule Logic      →  Confidence Level  →  CI/CD Decision
(age, state,           (conservative,     (LOW / MED / HIGH)   (report / block)
 activity, tags)        multi-signal)
```

Signals are combined conservatively.

Conflicting signals reduce confidence, not increase it.

**Example — conflicting signals in practice:**

| Signal | Observation | Effect |
|---|---|---|
| Disk attachment state | Unattached for 30+ days | Points toward HIGH |
| Recent write activity | Writes detected in last 7 days | Conflicts with abandonment |
| **Combined result** | | **MEDIUM** — conflict reduces confidence |

When signals point in opposite directions, CleanCloud defaults to the lower confidence tier.

## What CleanCloud Will NOT Infer

CleanCloud intentionally does NOT attempt to infer:

- Business criticality
- Whether deletion is safe
- Whether a resource is "unused forever"
- Whether a resource is managed by Terraform, Pulumi, or CloudFormation

Those decisions require human and organizational context.
CleanCloud surfaces candidates for review — nothing more.

**Note on cost estimates:** Some rules include an `estimated_monthly_cost` in finding details (e.g., idle NAT Gateways, old AMIs). These are calculated from resource properties (size, SKU, quantity) — not from billing APIs or spending data. They help prioritize review, not justify deletion.

## Age-Based Confidence (Examples)

Many rules use time as one input signal. Thresholds vary by rule and resource type:

| Rule | Age Threshold | Confidence |
|------|---------------|------------|
| AWS Unattached EBS Volumes | 7+ days | MEDIUM |
| AWS Unattached EBS Volumes | 14+ days | HIGH |
| AWS Unattached Elastic IPs | 30+ days | HIGH |
| AWS Detached ENIs | 60+ days | MEDIUM |
| AWS Old EBS Snapshots | 90+ days | MEDIUM |
| AWS Old AMIs | 180+ days | MEDIUM |
| AWS Idle NAT Gateways | 14+ days idle | MEDIUM |
| AWS Idle RDS Instances | 14+ days idle | HIGH |
| AWS Idle ELBs (no targets) | 14+ days idle | HIGH |
| AWS Idle ELBs (has targets) | 14+ days idle | MEDIUM |
| Azure Unattached Disks | 7+ days | MEDIUM |
| Azure Unattached Disks | 14+ days | HIGH |
| Azure Old Snapshots | 30+ days | MEDIUM |
| Azure Old Snapshots | 90+ days | HIGH |
| Azure Idle SQL Databases | 14+ days idle | HIGH |

Resources below these thresholds are not flagged — this prevents false positives on recently created or temporarily detached resources.

## State-Based Confidence (Deterministic)

Some rules use a single deterministic state check — no age threshold needed. These are binary signals with zero false positives:

| Rule | Signal | Confidence |
|------|--------|------------|
| AWS Infinite Retention Logs | No retention policy set | MEDIUM |
| AWS Untagged Resources | Zero tags on resource | MEDIUM |
| Azure Unused Public IPs | IP not attached to any resource | MEDIUM |
| Azure Untagged Resources (unattached disk) | Zero tags and not attached | MEDIUM |
| Azure Untagged Resources (snapshot/attached disk) | Zero tags | LOW |
| Azure Empty App Service Plans | Paid plan with zero apps | HIGH |
| Azure Empty Load Balancers | Standard LB with zero backend members | HIGH |
| Azure Empty App Gateways | All backend pools have zero targets | HIGH |
| Azure Idle VNet Gateways | No active connections | MEDIUM |
| Azure Stopped (Not Deallocated) VMs | Power state is 'Stopped' (not 'Deallocated') | HIGH |

## Using Confidence in CI/CD

Confidence levels are designed to integrate safely into CI/CD pipelines.

Recommended usage:

- Block pipelines only on HIGH confidence findings
- Review MEDIUM findings asynchronously
- Ignore LOW findings unless investigating drift

Example:

`cleancloud scan --provider aws --region us-east-1 --fail-on-confidence HIGH`

### Why HIGH confidence is safe for pipeline gating

HIGH confidence findings share these properties:

- **Deterministic signals** — binary states (e.g., zero associations) or long-lived thresholds (14+ days) that eliminate ephemeral false positives
- **IaC-resilient** — newly provisioned resources fall below age thresholds; recently modified resources show recent activity
- **No business inference** — HIGH confidence never assumes a resource is unused forever, only that observable signals are consistently strong
- **Stable across deploys** — a HIGH confidence finding won't flip to LOW on the next scan due to normal infrastructure churn

This makes `--fail-on-confidence HIGH` safe to use as a hard gate on production pipelines.

## Design Guarantees

CleanCloud guarantees that:

- Confidence levels are deterministic
- No machine learning or probabilistic models are used
- The same inputs always produce the same confidence
- Confidence logic is versioned and reviewed

### Versioning and backward compatibility

- Confidence logic is versioned alongside rule definitions
- Any change that promotes a finding's confidence (e.g., MEDIUM → HIGH) is treated as a breaking change and documented in the changelog
- CI/CD pipelines can pin to a specific CleanCloud version to avoid unexpected enforcement changes — important for teams with strict change management requirements
