# aws.ec2.instance.stopped — Canonical Rule Specification

## 1. Intent

Detect EC2 instances that are currently in the `stopped` state and have trusted
CloudTrail audit evidence that they became stopped at least the configured threshold
ago (default: 30 days), so they can be surfaced as cleanup review candidates.

This is a **read-only review-candidate rule**. It is not a delete-safe rule and not
proof that termination is operationally safe.

---

## 2. AWS API Grounding

Based on official EC2 and CloudTrail API and user-guide behavior.

### Key DescribeInstances fields

| Field | Behaviour |
|---|---|
| `InstanceId` | Unique instance identifier; always present |
| `State.Name` | Canonical instance state string (`stopped`, `running`, etc.) |
| `InstanceType` | Instance type |
| `Placement.AvailabilityZone` | AZ the instance is placed in |
| `RootDeviceType` | Root device type (`ebs`, `instance-store`) |
| `StateTransitionReason` | Diagnostic text describing last state transition |
| `StateReason.Code` | Machine-readable reason code |
| `StateReason.Message` | Human-readable reason message |
| `HibernationOptions.Configured` | Whether hibernation is configured |
| `BlockDeviceMappings[].Ebs.VolumeId` | Attached EBS volume IDs |
| `Tags` | Key-value tags |

### Key CloudTrail LookupEvents fields

| Field | Behaviour |
|---|---|
| `EventId` | Unique event identifier for deduplication |
| `CloudTrailEvent` | JSON string with full event detail |
| `CloudTrailEvent.eventTime` | ISO8601 UTC timestamp of the event |
| `CloudTrailEvent.eventName` | Event name (`StopInstances`, `StartInstances`, …) |
| `CloudTrailEvent.awsRegion` | Region the event occurred in |
| `CloudTrailEvent.recipientAccountId` | Account the event is billed to |
| `CloudTrailEvent.requestParameters.instancesSet.items[].instanceId` | Instance IDs targeted by the event |

### Critical AWS facts

1. **`stopped` state** is canonical (`State.Name == "stopped"`, code 80). Stopped instances
   do not incur compute charges; attached EBS volumes continue to incur storage charges.

2. **No canonical `stopped_since` timestamp** is exposed directly by EC2 APIs.
   `StateTransitionReason` and `StateReason` are diagnostic text only — not machine-readable
   trusted timestamp sources.

3. **CloudTrail event history** is enabled by default and provides an immutable,
   searchable record of the past 90 days of management events per Region.

4. **CloudTrail `LookupEvents`** returns events sorted most-recent-first and supports
   pagination. Results are limited to one account and one Region per query.

5. **Restart cycles**: a `StopInstances` event that predates a later `StartInstances`
   event for the same instance is stale and must not be used as the stop timestamp.

6. **Eventual consistency**: EC2 state changes and CloudTrail delivery may lag; recent
   stop events may not yet be visible.

### Rule-design consequence

- EC2 is a current-state source, not a trusted temporal source for "stopped for N days".
- Trusted stop timing must come from CloudTrail `eventTime` only.
- `StateTransitionReason`/`StateReason` are diagnostic context only; they must never
  independently produce findings.
- This rule intentionally prefers false negatives over false positives.

---

## 3. Scope

**Included:**
- All instances returned by `DescribeInstances` with `instance-state-name=stopped`
- `normalized_state == "stopped"`
- `trusted_stop_timestamp_source == "cloudtrail"`
- `stopped_age_days >= stopped_age_threshold_days`

**Excluded:**
- Instances missing `InstanceId` (malformed)
- Instances missing canonical state (malformed)
- Instances with `normalized_state != "stopped"`
- Instances with no trusted CloudTrail-backed stop event (`NO_TRUSTED_STOP_TIMESTAMP_SOURCE`)
- Instances whose `stopped_age_days < stopped_age_threshold_days`

---

## 4. Canonical Definitions

| Term | Definition |
|---|---|
| `instance_id` | Normalized from `instance.InstanceId` → `instance.instanceId` → absent |
| `normalized_state` | Normalized from `instance.State.Name` → `instance.instanceState.name` → absent |
| `trusted_stop_time` | `eventTime` of the latest qualifying `StopInstances` CloudTrail event |
| `trusted_stop_timestamp_source` | `"cloudtrail"` when CloudTrail-backed; `"none"` otherwise |
| `trusted_stop_event_time_source` | Concrete audit source, e.g. `"cloudtrail_lookup"` |
| `stopped_age_days` | `floor((now_utc - trusted_stop_time_utc).total_seconds() / 86400)` |
| `stop_index` | Region-scoped mapping: `instance_id → latest qualifying StopInstances event record` |

### Restart-cycle handling

For each instance:
1. Collect all `StopInstances` events with `awsRegion == region` from the lookup window.
2. Find the most recent `StartInstances` event time (if any).
3. Discard all `StopInstances` events whose `eventTime ≤ latest StartInstances eventTime`.
4. Select the latest remaining `StopInstances` event (`max(eventTime)`).
5. If no qualifying stop event remains → `trusted_stop_timestamp_source = "none"` → SKIP ITEM.

---

## 5. Signal Model (Strict Separation)

### Normalization Contract

All rule logic must operate on normalized fields only.

**Instance normalization:**

| Field | Derivation |
|---|---|
| `instance_id` | `instance.InstanceId` → `instance.instanceId` → absent (skip item if absent) |
| `normalized_state` | `instance.State.Name` → `instance.instanceState.name` → absent (skip item if absent) |
| `instance_type` | `instance.InstanceType` → `instance.instanceType` → `null` |
| `availability_zone` | `instance.Placement.AvailabilityZone` → `instance.placement.availabilityZone` → `null` |
| `root_device_type` | `instance.RootDeviceType` → `instance.rootDeviceType` → `null` |
| `stop_reason_text` | `instance.StateTransitionReason` → `instance.StateReason.Message` → `instance.stateReason.message` → `""` |
| `stop_reason_code` | `instance.StateReason.Code` → `instance.stateReason.code` → `null` |
| `hibernation_configured` | `instance.HibernationOptions.Configured` → `instance.hibernationOptions.configured` → `null` |
| `attached_volume_ids` | `[bdm.Ebs.VolumeId for bdm with valid Ebs.VolumeId]` |
| `attached_volume_count` | `len(attached_volume_ids)` |
| `tags` | `{tag.Key: tag.Value for tag in instance.Tags}` |

**CloudTrail event parsing:**

- Parse `CloudTrailEvent` JSON explicitly.
- Reject events where `awsRegion != scanned_region`.
- Reject events where `eventTime` is missing, has no timezone, or is after `now_utc`.
- Reject events where `requestParameters.instancesSet.items` is missing or malformed.
- Deduplicate by `eventId` before lifecycle ordering.
- Extract instance IDs from each `items[].instanceId` entry.
- Malformed events are silently ignored (not FAIL RULE).

### A. EXCLUSION_RULES

| Condition | Result |
|---|---|
| `instance_id` absent | **SKIP** (malformed) |
| `normalized_state` absent | **SKIP** (malformed) |
| `normalized_state != "stopped"` | **SKIP** |
| `trusted_stop_time` absent | **SKIP** (`NO_TRUSTED_STOP_TIMESTAMP_SOURCE`) |
| `stopped_age_days < stopped_age_threshold_days` | **SKIP** |

There must be **no** exclusion for `hibernation_configured`, `attached_volume_count`,
tags, instance type, `StateTransitionReason` content, or `StateReason` code.

### B. DETECTION_SIGNAL

| Condition | Result |
|---|---|
| `normalized_state == "stopped"`, `trusted_stop_time` present, `stopped_age_days >= stopped_age_threshold_days` | **EMIT** |

### C. CONTEXTUAL_SIGNALS (non-detecting)

| Signal | Effect |
|---|---|
| `stop_reason_text` | Evidence/details only (diagnostic context) |
| `stop_reason_code` | Evidence/details only (diagnostic context) |
| `hibernation_configured` | Evidence/details only |
| `tags` | Evidence/details only |
| `instance_type` | Evidence/details only |
| `attached_volume_count` / `attached_volume_ids` | Evidence/details only |
| `total_ebs_gib` | Evidence/details only (optional enrichment) |

---

## 6. Evaluation Order (Mandatory)

1. Retrieve instances via paginated `DescribeInstances` with `instance-state-name=stopped` filter; fail rule on error.
2. Normalize instance records; skip items with absent `instance_id` or `normalized_state`.
3. Retrieve CloudTrail `StopInstances` and `StartInstances` events via fully-paginated `LookupEvents` for the region; fail rule on error.
4. Build `stop_index` from parsed events: deduplicate by `eventId`, apply restart-cycle filtering, select `max(eventTime)` per instance.
5. Optionally enrich attached EBS sizes from `DescribeVolumes`; never fail rule on enrichment error.
6. For each normalized instance, apply EXCLUSION_RULES sequentially.
7. Emit findings for remaining eligible instances.

No raw AWS field access after Step 2.

---

## 7. Confidence Model

| Condition | Confidence |
|---|---|
| `trusted_stop_timestamp_source == "cloudtrail"` and threshold satisfied | `HIGH` |

**Mandatory rule:** No MEDIUM or LOW fallback finding. An instance is either proven
stopped for the threshold duration via CloudTrail-backed audit evidence (HIGH) or
not emitted at all.

---

## 8. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `MEDIUM` |

---

## 9. Cost Model

EBS volumes attached to a stopped instance continue to incur storage charges, but
accurate pricing requires region-aware and volume-type-aware data.

- Do not use a flat blended EBS rate (e.g. `$0.10/GB-month`).
- `estimated_monthly_cost_usd` must be `None`.
- `total_ebs_gib` may be included in `details` as contextual evidence.

---

## 10. Failure Behavior

### Required APIs

- `ec2:DescribeInstances` — failure → **FAIL RULE**
- `cloudtrail:LookupEvents` — failure → **FAIL RULE**

### CloudTrail parsing

- Malformed `CloudTrailEvent` JSON → silently ignore that event (not FAIL RULE)
- Missing `requestParameters`, `instancesSet`, or `items` → silently ignore that event
- Missing `eventTime` or non-UTC timestamp → silently ignore that event
- `eventTime > now_utc` → silently ignore that event
- Incomplete pagination → **FAIL RULE**

### Optional enrichment

- `ec2:DescribeVolumes` failure → continue without EBS size data; never fails the rule

---

## 11. Blind Spots

Every finding must disclose in `signals_not_checked`:

1. Planned reactivation or warm-standby intent not known
2. DR or migration intent not known
3. AWS control-plane dependencies outside current instance state not checked
4. Elastic IP costs are handled by a separate rule
5. EC2/CloudTrail eventual-consistency windows after recent state changes (including CloudTrail delivery delay)

---

## 12. Evidence Contract

Every finding **must** include all of the following (null allowed, never omitted):

| Field | Requirement |
|---|---|
| `evaluation_path` | Exactly `"stopped-instance-review-candidate"` |
| `instance_id` | Always present |
| `normalized_state` | Always `"stopped"` |
| `trusted_stop_timestamp_source` | Always `"cloudtrail"` |
| `trusted_stop_event_time_source` | Always `"cloudtrail_lookup"` |
| `trusted_stop_time` | Always present (ISO8601 UTC) |
| `trusted_stop_event_name` | Always `"StopInstances"` |
| `trusted_stop_event_id` | Always present |
| `trusted_stop_event_account_id` | Present or `null` |
| `stopped_age_days` | Always present |
| `stopped_age_threshold_days` | Always present |
| `instance_type` | Present or `null` |
| `availability_zone` | Present or `null` |
| `attached_volume_ids` | Always present (list, may be empty) |
| `attached_volume_count` | Always present |

Optional contextual fields:
- `root_device_type`, `stop_reason_code`, `stop_reason_text`, `hibernation_configured`,
  `tags`, `total_ebs_gib`, `cloudtrail_lookup_window_days`

---

## 13. Title and Reason Contract

| Field | Value |
|---|---|
| `title` | `"Stopped EC2 instance review candidate"` |
| `reason` | `"Instance has been in 'stopped' state for N days per trusted CloudTrail stop event (threshold: M days)"` |

**Hard rules:**
- Do NOT call the instance "safe to terminate"
- Do NOT use `StateTransitionReason` as the authoritative stop timestamp
- Do NOT emit a finding without a trusted CloudTrail-backed stop time

---

## 14. API and IAM Contract

**Required:** `ec2:DescribeInstances`, `cloudtrail:LookupEvents`

**Best-effort:** `ec2:DescribeVolumes`

### API usage constraints

- `DescribeInstances` must use `instance-state-name=stopped` filter and paginate fully
- `LookupEvents` must paginate fully for both `StopInstances` and `StartInstances`
- No early exit after partial CloudTrail matches
- `event.awsRegion` must exactly match the scanned region

---

## 15. Acceptance Scenarios

### Must emit

1. Instance `stopped`, latest trusted CloudTrail `StopInstances` age ≥ threshold → EMIT HIGH
2. Instance `stopped`, threshold met, attached EBS volumes present → EMIT; volume IDs in details
3. Instance `stopped`, threshold met, CloudTrail across multiple pages → EMIT (pagination exhausted)

### Must skip

1. Instance `stopped`, no CloudTrail `StopInstances` event found → SKIP (`NO_TRUSTED_STOP_TIMESTAMP_SOURCE`)
2. Instance `stopped`, CloudTrail `StopInstances` age < threshold → SKIP
3. Instance in `running`, `stopping`, `terminated` state → SKIP
4. Instance missing `InstanceId` → SKIP
5. Instance missing canonical state → SKIP
6. Instance previously stopped, then started, then stopped again → use only the latest stop after the most recent start; prior stop is stale

### Must fail

1. `DescribeInstances` request/pagination failure → FAIL RULE
2. `cloudtrail:LookupEvents` request/pagination failure → FAIL RULE

### Must NOT happen

1. MEDIUM or LOW confidence finding emitted
2. `StateTransitionReason` used to qualify a finding
3. Flat EBS cost estimate in `estimated_monthly_cost_usd`
4. Stop event from wrong region used
5. Stale stop event from before a later `StartInstances` event used
6. Early exit from CloudTrail pagination

---

## 16. In-File Contract

```
Rule: aws.ec2.instance.stopped

Intent:
    Detect EC2 instances that are currently stopped and have trusted CloudTrail
    audit evidence that they have been stopped for at least the configured threshold.

Exclusions:
    - instance_id absent (malformed)
    - normalized_state absent (malformed)
    - normalized_state != "stopped"
    - trusted_stop_time absent (NO_TRUSTED_STOP_TIMESTAMP_SOURCE)
    - stopped_age_days < stopped_age_threshold_days

Detection:
    - normalized_state == "stopped"
    - trusted_stop_timestamp_source == "cloudtrail"
    - stopped_age_days >= stopped_age_threshold_days

Key rules:
    - This is a review-candidate rule, not a delete-safe rule.
    - CloudTrail LookupEvents eventTime is the sole trusted stop-time source.
    - StateTransitionReason and StateReason are diagnostic context only.
    - No MEDIUM/LOW fallback findings — HIGH confidence only when CloudTrail-backed.
    - Restart cycles handled: use latest StopInstances after most recent StartInstances.
    - CloudTrail pagination must be exhausted; no early exit after partial matches.
    - Do not use flat blended EBS storage pricing for cost estimation.

Blind spots:
    - planned reactivation or warm-standby intent not known
    - DR or migration intent not known
    - AWS control-plane dependencies outside current instance state
    - EIP costs handled by another rule
    - EC2/CloudTrail eventual-consistency windows after recent state changes

APIs:
    - ec2:DescribeInstances
    - cloudtrail:LookupEvents
    - ec2:DescribeVolumes (optional enrichment)
```

---

## 17. Implementation Constants

| Constant | Value | Description |
|---|---|---|
| `_DEFAULT_STOPPED_AGE_THRESHOLD_DAYS` | `30` | Default minimum stopped age to emit a finding |
| `_DEFAULT_CLOUDTRAIL_LOOKUP_DAYS` | `90` | Default CloudTrail LookupEvents window (max for default history) |
