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

## Age-Based and State-Based Confidence

Each rule documents its own confidence logic, thresholds, and signals. See the canonical reference:

**→ [docs/rules.md](rules.md)**

The key patterns are:

- **Age-based rules** use time thresholds (e.g., 14+ days unattached) to avoid false positives on ephemeral resources. Resources below the threshold are not flagged.
- **State-based rules** use a single deterministic binary check (e.g., zero backend members, no retention policy) — no age threshold needed.

Conflicting signals always reduce confidence, never increase it.

## Using Confidence in Governance Scans

Confidence levels are designed for scheduled governance scans and optional enforcement gates.

Recommended usage:

- **Scheduled scans** (daily/weekly) — report all findings; triage HIGH first, review MEDIUM asynchronously, treat LOW as informational
- **Enforcement gates** (optional) — fail a scheduled job or PR scan if HIGH confidence waste exceeds a threshold

Example:

`cleancloud scan --provider aws --all-regions --fail-on-confidence HIGH`

### Why HIGH confidence is safe for enforcement

HIGH confidence findings share these properties:

- **Deterministic signals** — binary states (e.g., zero associations) or long-lived thresholds (14+ days) that eliminate ephemeral false positives
- **IaC-resilient** — newly provisioned resources fall below age thresholds; recently modified resources show recent activity
- **No business inference** — HIGH confidence never assumes a resource is unused forever, only that observable signals are consistently strong
- **Stable across scans** — a HIGH confidence finding won't flip to LOW on the next scan due to normal infrastructure churn

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
