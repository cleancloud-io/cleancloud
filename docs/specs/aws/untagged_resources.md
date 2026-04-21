# aws.resource.untagged — Canonical Rule Specification

## 1. Intent

Detect supported AWS resources in the currently evaluated account scope that have **no
current tags** according to authoritative service-native tagging APIs, so they can be
reviewed for governance, ownership, allocability, and FinOps hygiene gaps.

This is a **read-only hygiene rule**. It is not a waste rule, not proof that a resource is
unused, and not proof that the resource violates a mandatory tag policy.

---

## 2. AWS API Grounding

Based on official AWS tagging, EC2, S3, CloudWatch Logs, and Resource Groups Tagging API
documentation.

### Key AWS facts

1. AWS tags are key-value metadata used to organize, identify, and manage resources.
2. Tag keys and tag values are case sensitive.
3. AWS recommends that tags not contain confidential or sensitive data.
4. Resource Groups Tagging API `GetResources` returns resources that are **currently tagged or
   previously tagged** in the specified Region/account scope.
5. If `GetResources` is called without `TagFilters`, resources that were previously tagged but
   do not currently have tags are returned with `Tags: []`.
6. Because `GetResources` only returns currently tagged or previously tagged resources, it is
   **not** a complete inventory source for resources that were **never tagged**.
7. `DescribeVolumes` is the canonical EC2 API for enumerating EBS volumes in the evaluated
   Region and supports pagination.
8. `DescribeVolumes` volume objects include `VolumeId`, `AvailabilityZone`, `CreateTime`,
   `Size`, and `Tags`.
9. `ListBuckets` returns all general purpose S3 buckets owned by the authenticated sender and
   strongly recommends pagination.
10. `ListBuckets` is not supported for directory buckets.
11. `ListBuckets` supports `BucketRegion` filtering and can return `BucketRegion` and
    `BucketArn` in bucket objects.
12. `GetBucketTagging` returns the current tag set for a general purpose bucket.
13. `GetBucketTagging` returns special error `NoSuchTagSet` when no tag set is associated with
    the bucket.
14. `GetBucketTagging` is not supported for directory buckets.
15. `DescribeLogGroups` is the canonical CloudWatch Logs API for enumerating log groups in the
    evaluated Region and supports pagination.
16. `DescribeLogGroups` returns log-group inventory fields such as `logGroupName`, `arn`,
    `logGroupArn`, `creationTime`, and `logGroupClass`, but does **not** return tags.
17. `ListTagsForResource` is the authoritative API for current CloudWatch Logs resource tags
    and currently supports log groups and destinations.
18. CloudWatch Logs `DescribeLogGroups` can optionally include linked accounts in a monitoring
    account, but this is an explicit cross-account mode rather than a default same-account
    behavior.

### Implications

- This rule must use **service-native inventory plus service-native current-tag lookup**.
- Resource Groups Tagging API `GetResources` may be used only as contextual reference; it is
  not authoritative for complete untagged inventory.
- The rule must not claim coverage of **all AWS resources**.
- The canonical supported scope is limited to resource families with documented native
  inventory and current-tag retrieval contracts.
- The rule checks only whether a resource has **zero current tags**.
- This rule does **not** evaluate required tag keys, required tag values, or tag-policy
  compliance.
- `estimated_monthly_cost_usd = null`; missing tags are a governance/FinOps metadata issue,
  not a canonical AWS cost figure.

---

## 3. Canonical Scope

### Included resource families

1. **EBS volumes** in the currently evaluated Region via `DescribeVolumes`
2. **General purpose S3 buckets** owned by the current account via paginated `ListBuckets`
3. **CloudWatch Logs log groups** in the currently evaluated Region via `DescribeLogGroups`

### Excluded resource families / modes

1. AWS resources that do not have a documented native inventory + current-tag contract in this
   rule
2. Resources discoverable only through Resource Groups Tagging API `GetResources`
3. S3 **directory buckets**
4. CloudWatch Logs linked-source-account log groups unless cross-account mode is explicitly
   enabled by a separate design
5. Individual items whose current tag visibility cannot be retrieved from the required native
   tag source

---

## 4. Canonical Definitions

| Term | Definition |
|---|---|
| `untagged` | Resource has zero current tags from the authoritative tag source for its resource family |
| `tagged` | Resource has one or more current tags from the authoritative tag source |
| `current_tag_count` | Number of current tags returned by the authoritative tag source |
| `resource_family` | One of `ebs_volume`, `s3_bucket`, `cloudwatch_log_group` |
| `age_days` | Optional context only; `floor((now_utc − create_time_utc) / 86400)` when a documented creation timestamp is available and valid |

### Family-specific untagged definitions

| Resource family | Authoritative current-tag source | Untagged condition |
|---|---|---|
| `ebs_volume` | `DescribeVolumes.Tags` | `Tags` absent, empty list, or malformed/non-list after conservative normalization |
| `s3_bucket` | `GetBucketTagging.TagSet` | `NoSuchTagSet` or empty `TagSet` |
| `cloudwatch_log_group` | `ListTagsForResource.tags` | `tags` absent or empty map |

### Important tag semantics

- A resource is **tagged** when the authoritative source returns one or more current tag
  entries.
- This rule must not require specific tag keys or values.
- A current tag entry with an empty value is still a tag entry and therefore does **not**
  count as untagged.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

### Common normalized fields

| Canonical field | Meaning | Absent / invalid |
|---|---|---|
| `resource_family` | Canonical family identifier | skip item |
| `resource_id` | Stable native identifier | skip item |
| `resource_arn` | Native ARN when available | null |
| `native_region` | Native resource Region when available | null |
| `current_tag_count` | Count of current tags | skip item |
| `untagged_state` | `true` when `current_tag_count == 0` | skip item |
| `create_time_utc` | Native creation timestamp when documented and valid | null |
| `age_days` | Context-only age derived from `create_time_utc` | null |

### Resource-family normalization

| Resource family | Required normalized fields | Optional context |
|---|---|---|
| `ebs_volume` | `resource_id = VolumeId`, `current_tag_count = len(Tags or [])`, `native_region = evaluated_region` | `availability_zone`, `size_gib`, `volume_type`, `encrypted`, `state`, `create_time_utc`, `age_days` |
| `s3_bucket` | `resource_id = Name`, `current_tag_count = len(TagSet)`, `native_region = BucketRegion when available` | `resource_arn = BucketArn`, `create_time_utc = CreationDate when valid`, `age_days` |
| `cloudwatch_log_group` | `resource_id = logGroupName`, `current_tag_count = len(tags)`, `resource_arn = logGroupArn or arn`, `native_region = evaluated_region` | `log_group_class`, `creation_time_utc`, `age_days` |

### Normalization requirements

- String-valued identifiers must normalize only from non-empty strings.
- Timestamp fields are contextual only; if present they must be timezone-aware UTC before
  age calculation. Invalid or missing timestamps must not suppress detection.
- EBS `Tags` must normalize conservatively: non-list values are treated as empty for
  current-tag-count purposes.
- `current_tag_count` must be based only on the family-specific authoritative current-tag
  source.
- If an item’s authoritative current-tag source is unavailable for that item, the item must
  be skipped.

---

## 6. Canonical Rule Statement

A supported resource is eligible for this rule only when **all** of the following are true:

- stable native identity exists
- the resource belongs to a canonical supported resource family
- authoritative current-tag visibility for that item is available
- `current_tag_count == 0`

No additional predicate may be required for baseline eligibility, including:

- resource age
- resource usage/activity
- cost amount
- encryption status
- retention configuration
- attachment state
- required-tag-key policy
- tag-policy compliance result

---

## 7. Deterministic Evaluation Order

1. Enumerate supported EBS volumes via paginated `DescribeVolumes`.
2. Enumerate supported S3 general purpose buckets via paginated `ListBuckets`.
3. Enumerate supported CloudWatch log groups via paginated `DescribeLogGroups`.
4. Normalize each item using the family-specific normalization contract.
5. For each normalized item:
   - missing stable identity → **SKIP ITEM**
   - unsupported / out-of-scope family → **SKIP ITEM**
   - required current-tag visibility unavailable → **SKIP ITEM**
   - `current_tag_count > 0` → **SKIP ITEM**
   - `current_tag_count == 0` → **EMIT**

---

## 8. Failure Behavior

### Rule-level failures (FAIL RULE)

- `ec2:DescribeVolumes` request/pagination failure
- `s3:ListBuckets` request/pagination failure
- `logs:DescribeLogGroups` request/pagination failure
- permission failures for required inventory APIs

### Item-level skips (SKIP ITEM)

- malformed identity for the specific item
- S3 bucket `GetBucketTagging` failure other than `NoSuchTagSet`
- CloudWatch Logs `ListTagsForResource` failure for the specific log group
- unsupported S3 directory bucket
- unavailable current-tag visibility for the specific item

### Special handling rules

- S3 `NoSuchTagSet` means **untagged**, not failure
- S3 buckets that prove out-of-scope native tag lookup behavior, such as unsupported
  directory-bucket `GetBucketTagging`, must be **SKIP ITEM**
- Resource Groups Tagging API must not be required for correctness of this rule

---

## 9. Confidence Model

| Condition | Confidence |
|---|---|
| Finding emitted from authoritative current-tag source with zero current tags | `HIGH` |

**Mandatory rule:** use `HIGH` confidence. The rule observes a direct configuration fact:
the supported resource currently has zero tags in its authoritative native tag source.

---

## 10. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `MEDIUM` |

**Mandatory rule:** use `MEDIUM` risk. Missing tags are an ownership, governance, and
allocability concern, but they do not by themselves prove direct security exposure, service
failure, or deletability.

---

## 11. Cost Model

**Canonical cost rule:** `estimated_monthly_cost_usd = null`.

### Mandatory rules

- MUST NOT infer waste purely from missing tags
- MUST NOT emit a cost estimate from resource size, age, or storage alone
- MAY include family-specific size or age context only

---

## 12. Evidence / Details Contract

### Required details fields

Each emitted finding must include, at minimum:

```text
evaluation_path             = "untagged-supported-resource"
resource_family
resource_id
current_tag_count           = 0
native_region
resource_arn
create_time
age_days
tag_source_api
```

### Allowed `tag_source_api` values

- `ec2:DescribeVolumes`
- `s3:GetBucketTagging`
- `logs:ListTagsForResource`

### Required evidence wording

Signals used should state:

- supported native resource family was identified
- authoritative current-tag source was consulted
- no current tags were present at evaluation time

Signals not checked should state major blind spots, such as:

- whether the resource is intentionally exempt from tagging
- whether specific required business tags should exist
- whether the effective AWS Organizations tag policy marks the resource compliant
- application/service criticality
- planned future usage
- exact cost impact

---

## 13. Non-goals / Blind Spots

This rule does **not** prove any of the following:

- that the resource is unused
- that the resource is waste
- that the resource violates a required-key or required-value policy
- that the resource is noncompliant with AWS Organizations tag policy
- that the resource lacks equivalent ownership metadata outside AWS tags
- that deleting or modifying the resource is safe

---

## 14. API and IAM Contract

### Required APIs

- `ec2:DescribeVolumes`
- `s3:ListAllMyBuckets`
- `s3:GetBucketTagging`
- `logs:DescribeLogGroups`
- `logs:ListTagsForResource`

### Mandatory API usage rules

- `DescribeVolumes` must be paginated
- `ListBuckets` must be paginated
- `DescribeLogGroups` must be paginated
- `DescribeLogGroups` must not assume that tags are present in inventory objects
- `ListTagsForResource` must use the log-group ARN/name shape documented by CloudWatch Logs
- `GetResources` from Resource Groups Tagging API must not be used as the sole inventory
  source for untagged detection

---

## 15. Acceptance Scenarios

### Must emit

1. EBS volume with `VolumeId` present and `Tags` absent
2. EBS volume with `VolumeId` present and `Tags == []`
3. S3 general purpose bucket where `GetBucketTagging` returns `NoSuchTagSet`
4. S3 general purpose bucket where `GetBucketTagging.TagSet == []`
5. CloudWatch log group where `ListTagsForResource.tags == {}`
6. CloudWatch log group where `ListTagsForResource.tags` is absent/empty

### Must skip

1. EBS volume with one or more current tags
2. S3 bucket with one or more current tags
3. CloudWatch log group with one or more current tags
4. malformed EBS volume without `VolumeId`
5. malformed S3 bucket without `Name`
6. malformed log group without `logGroupName`
7. S3 bucket where current tag visibility fails for reasons other than `NoSuchTagSet`
8. CloudWatch log group where `ListTagsForResource` fails
9. S3 directory bucket

### Must fail

1. `DescribeVolumes` inventory failure
2. `ListBuckets` inventory failure
3. `DescribeLogGroups` inventory failure

---

Rule: aws.resource.untagged
