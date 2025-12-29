# CleanCloud Rules

Complete reference for all hygiene rules implemented by CleanCloud.

---

## Design Principles

All CleanCloud rules follow these principles:

### 1. Read-Only Always
- Uses read-only cloud APIs exclusively
- No `Delete*`, `Modify*`, `Tag*`, or `Update*` operations
- Safe for production environments

### 2. Conservative by Default
- Multiple signals preferred over single indicators
- Age-based thresholds prevent false positives on temporary resources
- Prefer false negatives over false positives

### 3. Explicit Confidence Levels
Every finding includes a confidence level:
- **HIGH** - Multiple strong signals, very likely orphaned
- **MEDIUM** - Moderate signals, worth reviewing
- **LOW** - Weak signals, informational only

### 4. Review-Only Recommendations
- Findings are candidates for human review, not automated action
- Clear reasoning provided for each finding
- No rule should justify deletion on its own

---

## AWS Rules (4 Total)

### 1. Unattached EBS Volumes

**Rule ID:** `aws.ebs.volume.unattached`

**What it detects:** EBS volumes not attached to any EC2 instance

**Confidence:**
- **HIGH:** Unattached ≥ 14 days
- **MEDIUM:** Unattached 7-13 days
- Not flagged: < 7 days

**Why this threshold:**
- Allows time for deployment cycles
- Accounts for rollback windows
- Reduces false positives from autoscaling

**Common causes:**
- Volumes from terminated EC2 instances
- Failed deployments or rollbacks
- Autoscaling cleanup gaps

**Required permission:** `ec2:DescribeVolumes`

---

### 2. Old EBS Snapshots

**Rule ID:** `aws.ebs.snapshot.old`

**What it detects:** Snapshots ≥ 365 days old

**Confidence:**
- **HIGH:** Age ≥ 365 days

**Limitations:**
- Does NOT check AMI linkage (by design, avoids false positives)
- Does NOT verify snapshot is unused (conservative approach)

**Common causes:**
- Backup retention policies without lifecycle rules
- Snapshots from deleted volumes
- Over-retention without cleanup

**Required permission:** `ec2:DescribeSnapshots`

---

### 3. CloudWatch Log Groups (Infinite Retention)

**Rule ID:** `aws.cloudwatch.logs.infinite_retention`

**What it detects:** Log groups with no retention policy

**Confidence:**
- **HIGH:** No retention policy, ≥ 30 days old

**Why this matters:**
- Logs grow indefinitely without retention
- Can reach GBs/TBs over months
- Often forgotten after service decommission

**Common causes:**
- Default CloudFormation behavior (no retention)
- Manual log group creation
- Missing lifecycle policies

**Required permission:** `logs:DescribeLogGroups`

---

### 4. Untagged Resources

**Rule ID:** `aws.resource.untagged`

**What it detects:** Resources with zero tags

**Resources checked:**
- EBS volumes
- S3 buckets
- CloudWatch log groups

**Confidence:**
- **MEDIUM:** Zero tags (always MEDIUM, never HIGH)

**Why this matters:**
- Ownership ambiguity
- Compliance violations (SOC2, ISO27001)
- Cleanup decision paralysis

**Required permissions:**
- `ec2:DescribeVolumes`
- `s3:GetBucketTagging`
- `logs:ListTagsLogGroup`

---

## Azure Rules (4 Total)

### 1. Unattached Managed Disks

**Rule ID:** `azure.unattached_managed_disk`

**What it detects:** Managed disks not attached to any VM

**Confidence:**
- **HIGH:** Unattached ≥ 14 days
- **MEDIUM:** Unattached 7-13 days
- Not flagged: < 7 days

**Detection logic:**
```python
if disk.managed_by is None:  # Not attached
    age_days = calculate_age(disk.time_created)
```

**Common causes:**
- Disks from deleted VMs
- Failed deployments
- Autoscaling cleanup gaps

**Required permission:** `Microsoft.Compute/disks/read`

---

### 2. Old Managed Disk Snapshots

**Rule ID:** `azure.old_snapshot`

**What it detects:** Snapshots older than configured thresholds

**Confidence:**
- **HIGH:** Age ≥ 90 days
- **MEDIUM:** Age ≥ 30 days

**Limitations:**
- Does NOT check if snapshot is referenced by images
- Conservative to avoid false positives

**Common causes:**
- Snapshots from backup jobs
- Over-retention without lifecycle policies
- Snapshots from deleted disks

**Required permission:** `Microsoft.Compute/snapshots/read`

---

### 3. Unused Public IP Addresses

**Rule ID:** `azure.public_ip_unused`

**What it detects:** Public IPs not attached to any network interface

**Confidence:**
- **HIGH:** Not attached (deterministic state)

**Why this matters:**
- Public IPs incur charges even when unused
- State is deterministic (no heuristics needed)

**Detection logic:**
```python
if public_ip.ip_configuration is None:
    confidence = "HIGH"
```

**Required permission:** `Microsoft.Network/publicIPAddresses/read`

---

### 4. Untagged Resources

**Rule ID:** `azure.untagged_resource`

**What it detects:** Resources with zero tags

**Resources checked:**
- Managed disks (7+ days old)
- Snapshots

**Confidence:**
- **MEDIUM:** Untagged disk that's also unattached
- **LOW:** Untagged snapshot or attached disk

**Required permissions:**
- `Microsoft.Compute/disks/read`
- `Microsoft.Compute/snapshots/read`

---

## Rule Stability Guarantee

Once a rule reaches production status:
- ✅ Rule ID remains stable
- ✅ Confidence semantics unchanged
- ✅ Backwards compatibility preserved
- ✅ Schema additions only (no breaking changes)

This guarantees trust for long-running CI/CD integrations.

---

## Coming Soon

**AWS:**
- Unused Elastic IPs
- Old AMIs (>180 days)
- Unused EBS encryption keys

**Azure:**
- Unused Network Interfaces
- Old VM images
- Orphaned storage accounts

**Multi-Cloud:**
- GCP support

---

**Next:** [AWS Setup →](aws.md) | [Azure Setup →](azure.md) | [CI/CD Integration →](ci.md)