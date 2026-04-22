# aws.ec2.ami.old — Canonical Rule Specification

## 1. Intent

Detect self-owned, available EC2 AMIs that are likely stale lifecycle candidates for cleanup review because they are either:

- explicitly deprecated by the owner, or
- non-deprecated but sufficiently old/stale with no strong evidence of current use.

This is a **read-only hygiene rule**. It is not a deletion rule, lifecycle automation, or safety guarantee.

---

## 2. AWS API Grounding

Based on AWS EC2 / Auto Scaling APIs:

### Key AWS facts

| Field | Behaviour |
|---|---|
| `creationDate` | Always present on EC2 Image |
| `deprecationTime` | Owner-managed lifecycle metadata |
| `lastLaunchedTime` | Last EC2 launch timestamp using this AMI; ~24h ingestion delay; partial historical coverage |
| `state == "available"` | Required for evaluation |
| `DescribeImageAttribute(lastLaunchedTime)` | Valid API for fetching last launch time |
| `DescribeLaunchTemplateVersions` | Supports `image-id` filter; supports `$Default`, `$Latest` version aliases |
| `DescribeLaunchConfigurations` | Has **no** `ImageId` filter — full scan required |

### Rule implication

AWS does NOT provide full certainty of non-use → this rule is **probabilistic hygiene detection**.

---

## 3. Scope

**Included:**
- `Owners = ["self"]`
- `state == "available"`
- Region-scoped AMIs

**Excluded:**
- Non-owned AMIs
- Non-available AMIs
- Malformed records without `ImageId`

---

## 4. Canonical Definitions

| Term | Definition |
|---|---|
| `age_days` | `now − creationDate` |
| `recently_active_days` | 30 (default) |
| `max_age_days` | 180 (default) |
| `staleLastLaunch` | `lastLaunchedTime` exists AND `days_since_last_launch >= max_age_days` |

### Missing `lastLaunchedTime` rule

Treated as **UNKNOWN**. MUST NOT be used for:
- scoring
- exclusion
- positive inference

---

## 5. Signal Model (Strict Separation)

**No cross-bucket influence allowed.**

### A. EXCLUSION_RULES (non-deprecated only)

Hard skip conditions:

| Condition | Result |
|---|---|
| `lastLaunchedTime` exists AND `days_since_last_launch < recently_active_days` | **SKIP** |
| Running OR pending instances exist using AMI | **SKIP** |

**Critical rules:**
- Missing `lastLaunchedTime` → does **NOT** trigger exclusion
- `EXCLUSION_RULES` do **NOT** apply to deprecated AMIs

### B. SCORING_SIGNALS

Only scoring inputs allowed. Score range: 0–2.

| Signal | Points |
|---|---|
| `age_days >= max_age_days` | +1 |
| `staleLastLaunch == true` | +1 |

`score == 0` → **SKIP**

### C. CONTEXTUAL_SIGNALS (non-scoring)

May only:
- downgrade confidence (max **1 level total**)
- appear in evidence

**Includes:**
- Launch template references
- Launch configuration references
- Snapshot / volume metadata
- API visibility gaps

**Hard rules:**
- Never affects score
- Never creates findings
- Max one total confidence downgrade per AMI

---

## 6. Evaluation Order (Mandatory)

1. Parse + normalize inputs
2. Check deprecation override
3. Apply `EXCLUSION_RULES` (non-deprecated only)
4. Compute `SCORING_SIGNALS`
5. Apply `CONTEXTUAL_SIGNALS`
6. Assign confidence
7. Assign risk
8. Build evidence

---

## 7. Path Logic

### Path A — Deprecated override

**Condition:** `deprecationTime` exists AND valid AND `<= now` AND `state == "available"`

**Result:**
- MUST emit finding
- `confidence = HIGH`
- Active instances do **NOT** suppress
- Recent launch does **NOT** suppress
- Contextual signals do **NOT** suppress or modify confidence

**Invalid `deprecationTime`:** treat as non-deprecated (Path B)

### Path B — Non-deprecated scored

1. Apply `EXCLUSION_RULES` → skip if matched
2. Compute score:
   - `0` → skip
   - `1` → `LOW`
   - `2` → `MEDIUM`
3. Apply contextual downgrade (max 1 level total)

---

## 8. Confidence Model

**Confidence = evidence strength (not urgency)**

| Condition | Confidence |
|---|---|
| Deprecated AMI (`available`) | `HIGH` |
| Score 2 (no contextual downgrade) | `MEDIUM` |
| Score 2 + contextual downgrade | `LOW` |
| Score 1 | `LOW` |

**Hard rules:**
- Contextual signals **never increase** confidence
- Max **one** downgrade regardless of how many contextual triggers fire

---

## 9. Risk Model

**Risk = operational urgency (independent of confidence)**

| Condition | Risk |
|---|---|
| Deprecated + active instances exist | `HIGH` |
| Deprecated + no active instances | `MEDIUM` |
| Non-deprecated + `age_days >= max_age_days` + `staleLastLaunch == true` (score 2) | `MEDIUM` |
| Non-deprecated + age only (score 1) | `LOW` |

**Guardrail:** `score == 2` → risk **MUST** be `>= MEDIUM` (unless excluded earlier)

---

## 10. Active Instance Handling

**Query:** `image-id` filter, `state in [running, pending]`

| Path | Behaviour |
|---|---|
| Non-deprecated | Active instances = **EXCLUSION** (hard skip) |
| Deprecated | Do **not** suppress; active instances increase urgency (`HIGH` risk) |

---

## 11. LT / LC Handling

| Source | Strategy |
|---|---|
| Launch templates | Best-effort; prefer `$Default + $Latest` versions; full traversal optional |
| Launch configurations | Full scan allowed (`DescribeLaunchConfigurations` has no `ImageId` filter) |

**Hard rules:**
- LT/LC **never** affects score
- LT/LC max **1** confidence downgrade total
- LT/LC **never** creates findings

---

## 12. Cost Model

**Informational only.** MUST NOT affect score, confidence, or risk.

**Allowed:** upper-bound estimate using declared EBS volume size only (`declared_gb × $0.05/month`).

**Required warning in output:** `AMI metadata ≠ actual snapshot billing`

---

## 13. Failure Behavior

### Required API

`DescribeImages` → failure = **rule fails** (raises `PermissionError`)

### Best-effort APIs

- `DescribeImageAttribute`
- `DescribeInstances`
- LT / LC lookups

**General rule:** never fail scan due to best-effort APIs; always add `signals_not_checked`.

---

## 🔴 CRITICAL — Conservative Behavior (Active Instance Safety)

If active-instance check is unavailable, it **MUST NOT** be interpreted as:
- "no active instances"
- "AMI is unused"
- "safe to include"

### Mandatory handling for non-deprecated AMIs

Missing active-instance visibility = **UNKNOWN state**. Must be handled conservatively:
- Prefer **SKIP** if exclusion logic depends on absence of active instances, **OR**
- Downgrade evidence strength

**Absolute rule:** absence of evidence ≠ evidence of absence

### Conservative evaluation requirement

If **all** of the following are true:
- Non-deprecated AMI
- Scoring is borderline (`score == 1`)
- Active-instance visibility is unavailable

→ **prefer SKIP over emission**

---

## 14. Blind Spots

Must explicitly state in every finding's `signals_not_checked`:

1. `lastLaunchedTime` is delayed (~24h)
2. `lastLaunchedTime` is incomplete historically (coverage from April 2017 only)
3. LT/LC does not prove active ASG usage
4. No compliance / retention context available
5. Snapshot billing ≠ AMI metadata volume size

---

## 15. Evidence Contract

Every finding **must** include all of the following (null allowed, never omitted):

| Field | Requirement |
|---|---|
| `evaluation_path` | Exactly `"deprecated"` or `"scored"` (see 17) |
| `age_days` | Always present |
| `state` | Always present |
| `deprecation status` | Always present |
| `last launch status` | Present OR null |
| `active instance status` | Present OR null |
| `LT refs` | Present OR null |
| `LC refs` | Present OR null |
| `snapshot/volume metadata` | Present OR null |

`signals_not_checked` must contain:
- Permission / visibility gaps (listed first)
- Conceptual blind spots (always appended)

---

## 16. Title Contract

| Condition | Title |
|---|---|
| Deprecated + active instances | `"Deprecated AMI Still In Use"` |
| Deprecated, no active instances | `"Deprecated AMI"` |
| Non-deprecated + `staleLastLaunch` | `"Unused AMI"` |
| Non-deprecated + age only | `"AMI Older Than <max_age_days> Days"` |

**Hard rule:** Never label `"Unused"` if active instances exist.

---

## 17. Evaluation Path Naming (Fixed)

Evaluation path MUST be exactly one of:
- `deprecated`
- `scored`

No variants allowed.

---

## 18. Acceptance Scenarios

### Must emit

- Deprecated, available, no active instances
- Deprecated, available, active instances (HIGH risk)
- Non-deprecated, `age >= 180`, stale launch `>= 180`, no exclusions
- Non-deprecated, age-only stale (score 1)

### Must skip

- Non-deprecated, recently launched (`days_since_last_launch < 30`)
- Non-deprecated, active instances exist
- Non-deprecated, `score == 0`
- Malformed AMI without `ImageId`

### Must degrade (not fail)

- Missing best-effort API permissions
- Partial LT/LC visibility

### Must NOT happen

- LT/LC alone creates a finding
- Cost affects score, confidence, or risk
- Missing `lastLaunchedTime` triggers exclusion
- Contextual signals stack more than one confidence downgrade
- Absence of active-instance data treated as "no instances"

---

## 19. In-File Contract

Every implementation file must include this comment block verbatim:

```
# Rule: aws.ec2.ami.old
#
# Intent:
#   Detect self-owned available AMIs that are likely stale lifecycle candidates.
#
# Signal classes:
#   EXCLUSION (non-deprecated only)
#   SCORING
#   CONTEXTUAL
#
# Key rules:
#   - Deprecated AMIs always emit HIGH-confidence findings.
#   - Missing lastLaunchedTime is neutral.
#   - Missing active-instance data is UNKNOWN (never treated as "none").
#   - LT/LC never affect score; max one confidence downgrade total.
#   - Cost is informational only.
#
# Blind spots:
#   lastLaunchedTime is delayed/incomplete.
#   LT/LC does not prove ASG usage.
#   snapshot billing differs from AMI metadata.
#
# APIs:
#   Required:    ec2:DescribeImages
#   Best-effort: ec2:DescribeImageAttribute, ec2:DescribeInstances,
#                ec2:DescribeLaunchTemplates, ec2:DescribeLaunchTemplateVersions,
#                autoscaling:DescribeLaunchConfigurations
```

---

## 20. Implementation Constants

| Constant | Default | Description |
|---|---|---|
| `_RECENTLY_ACTIVE_DAYS` | `30` | Exclusion window for recent launches |
| `_DEFAULT_MAX_AGE_DAYS` | `180` | Age threshold for Path B scoring |
| `_LT_INDEX_GUARD` | `1 000` | Max LTs before truncating Phase 1 list |
| `_LC_INDEX_GUARD` | `5 000` | Max LCs before stopping pagination |
