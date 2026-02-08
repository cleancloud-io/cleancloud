# Confidence Levels in CleanCloud

CleanCloud assigns an explicit confidence level to every finding:
**LOW**, **MEDIUM**, or **HIGH**.

Confidence represents **how safe it is to review a resource as potentially abandoned** —
not how much money it might save, and not a recommendation to delete anything.

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

Signals are combined conservatively.

Conflicting signals reduce confidence, not increase it.

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
| Azure Unattached Disks | 7+ days | MEDIUM |

Resources below these thresholds are not flagged — this prevents false positives on recently created or temporarily detached resources.

## Using Confidence in CI/CD

Confidence levels are designed to integrate safely into CI/CD pipelines.

Recommended usage:

- Block pipelines only on HIGH confidence findings
- Review MEDIUM findings asynchronously
- Ignore LOW findings unless investigating drift

Example:

`cleancloud scan --provider aws --region us-east-1 --fail-on-confidence HIGH`

## Design Guarantees

CleanCloud guarantees that:

- Confidence levels are deterministic
- No machine learning or probabilistic models are used
- The same inputs always produce the same confidence
- Confidence logic is versioned and reviewed
