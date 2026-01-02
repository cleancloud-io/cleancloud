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

CleanCloud will never assign HIGH confidence based on a single signal.

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
- Cost impact
- Whether deletion is safe
- Whether a resource is “unused forever”
- Whether a resource is managed by Terraform, Pulumi, or CloudFormation

Those decisions require human and organizational context.
CleanCloud surfaces candidates for review — nothing more.

## Age-Based Confidence (Example)

Many rules use time as one input signal.

For example:
- A resource detached for 2 days → LOW
- Detached for 7–13 days → MEDIUM
- Detached for 14+ days → HIGH

Exact thresholds vary by rule and cloud provider.

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
