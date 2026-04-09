# CleanCloud Rules

Complete reference for all 32 rules implemented by CleanCloud (30 hygiene + 2 AI/ML).

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

## Quick Reference

**AWS:**

| Rule ID | Cost Surface | What It Detects |
|---|---|---|
| `aws.ec2.instance.stopped` | Compute | EC2 instances stopped 30+ days (EBS charges continue) |
| `aws.ec2.security_group.unused` | Governance | Security groups with no ENI associations |
| `aws.ebs.volume.unattached` | Storage | EBS volumes not attached to any instance |
| `aws.ebs.snapshot.old` | Storage | Snapshots ≥ 90 days old |
| `aws.ec2.ami.old` | Storage | AMIs older than 180 days |
| `aws.ec2.elastic_ip.unattached` | Network | Elastic IPs allocated 30+ days with no attachment |
| `aws.ec2.eni.detached` | Network | Detached ENIs 60+ days old |
| `aws.ec2.nat_gateway.idle` | Network | NAT Gateways with zero traffic 14+ days |
| `aws.elbv2.alb.idle` / `aws.elbv2.nlb.idle` / `aws.elb.clb.idle` | Network | Load balancers with zero traffic 14+ days |
| `aws.rds.instance.idle` | Platform | RDS instances with zero connections 14+ days |
| `aws.rds.snapshot.old` | Storage | Manual RDS snapshots older than 90 days |
| `aws.cloudwatch.logs.infinite_retention` | Observability | Log groups with no retention policy |
| `aws.resource.untagged` | Governance | EC2/S3/CloudWatch resources with zero tags |
| `aws.sagemaker.endpoint.idle` | AI/ML | SageMaker endpoints with zero invocations 14+ days *(opt-in: `--category ai`)* |
| `aws.sagemaker.notebook.idle` | AI/ML | SageMaker Notebook Instances InService with no activity 14+ days *(opt-in: `--category ai`)* |

**Azure:**

| Rule ID | Cost Surface | What It Detects |
|---|---|---|
| `azure.vm.stopped_not_deallocated` | Compute | Stopped but not deallocated VMs (full charges) |
| `azure.compute.disk.unattached` | Storage | Managed disks not attached to any VM |
| `azure.compute.snapshot.old` | Storage | Snapshots older than 30–90 days |
| `azure.network.public_ip.unused` | Network | Public IPs not attached to any interface |
| `azure.load_balancer.no_backends` | Network | Standard LBs with zero backend members |
| `azure.application_gateway.no_backends` | Network | App Gateways with zero backend targets |
| `azure.virtual_network_gateway.idle` | Network | VPN/ExpressRoute Gateways with no connections |
| `azure.app_service_plan.empty` | Platform | Paid App Service Plans with zero apps |
| `azure.app_service.idle` | Platform | App Services with zero HTTP requests 14+ days |
| `azure.sql.database.idle` | Platform | Azure SQL databases with zero connections 14+ days |
| `azure.container_registry.unused` | Platform | Container registries with no pulls 90+ days |
| `azure.resource.untagged` | Governance | Disks and snapshots with zero tags |
| `azure.aml.compute.idle` | AI/ML | AML compute clusters with min_node_count > 0 and no active nodes 14+ days *(opt-in: `--category ai`)* |
| `azure.ml.compute_instance.idle` | AI/ML | Azure ML Compute Instances Running with no control-plane activity 14+ days *(opt-in: `--category ai`)* |

**GCP:**

| Rule ID | Cost Surface | What It Detects |
|---|---|---|
| `gcp.compute.vm.stopped` | Compute | TERMINATED VM instances stopped 30+ days (disk charges continue) |
| `gcp.compute.disk.unattached` | Storage | Persistent Disks in READY state with no attached VM |
| `gcp.compute.snapshot.old` | Storage | Disk snapshots older than 90 days |
| `gcp.compute.ip.unused` | Network | Reserved static IPs (regional and global) in RESERVED state |
| `gcp.sql.instance.idle` | Platform | Cloud SQL instances with zero connections for 7+ days |
| `gcp.vertex.endpoint.idle` | AI/ML | Vertex AI Online Prediction endpoints with dedicated capacity and zero predictions for 14+ days (`--category ai`) |

---

## AWS Rules

### Compute Waste

#### Stopped EC2 Instances

**Rule ID:** `aws.ec2.instance.stopped`

**What it detects:** EC2 instances in 'stopped' state for 30+ days

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Stop time parsed from `StateTransitionReason` ≥ 30 days ago (deterministic timestamp)
- Not flagged: stop time unparseable or < 30 days ago

**Risk:** MEDIUM

**Why this matters:**
- Stopped EC2 instances do not charge for compute — but every attached EBS volume accrues storage costs at ~$0.10/GB-month, every hour, regardless of instance state
- A 500 GB root + data volume on a forgotten stopped instance costs ~$50/month indefinitely
- Any associated Elastic IPs continue to charge ~$0.005/hour while unattached
- Stopped instances are the most common form of "I meant to clean that up" infrastructure debt

**Detection logic:**
```python
for instance in describe_instances(state=stopped):
    stop_time = parse_state_transition_reason(instance.StateTransitionReason)
    # Format: "User initiated (YYYY-MM-DD HH:MM:SS UTC)"
    if stop_time and (now - stop_time).days >= 30:
        cost = sum(volume.size_gb for volume in attached_volumes) * $0.10
        confidence = "HIGH"  # Deterministic timestamp, not a heuristic
```

**Cost estimates:**
- Based on total attached EBS storage × $0.10/GB-month
- Example: 2 × 100 GB volumes = ~$20/month in ongoing storage charges
- Additional Elastic IP charges are tracked separately by the `aws.ec2.elastic_ip.unattached` rule

**Common causes:**
- Test or dev instances left stopped after a project ended
- Migration source instances never terminated after cutover
- Incident response boxes started and never cleaned up
- Autoscaling warm pools drained but not terminated

**Required permissions:**
- `ec2:DescribeInstances`
- `ec2:DescribeVolumes`

---

#### Unused Security Groups

**Rule ID:** `aws.ec2.security_group.unused`

**What it detects:** Security groups not associated with any network interface

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** No ENI associations found (service-managed groups may appear unused between deployments)

**Risk:** LOW

**Why this matters:**
- Security groups with no ENI associations are pure governance debt
- Each unused group widens the blast radius if a misconfiguration is later introduced
- Compliance audits (SOC 2, ISO 27001, PCI DSS) flag unused security groups as a control failure
- In accounts with hundreds of groups, unused ones obscure the real security posture and add friction to every access review
- Cost is indirect but real: engineer time spent auditing and explaining phantom groups in compliance reviews

**Detection logic:**
```python
in_use_sg_ids = {
    group["GroupId"]
    for eni in describe_network_interfaces()
    for group in eni["Groups"]
}
for sg in describe_security_groups():
    if sg.name != "default" and sg.id not in in_use_sg_ids:
        confidence = "MEDIUM"
```

**Exclusions:**
- `default` security groups — AWS prevents deletion of the default group; flagging it is noise

**Caveats:**
- A security group referenced only in another group's inbound rules (not attached to any ENI) will be flagged. This is intentional.
- Service-managed groups (RDS, ELB, Lambda) may appear unused briefly between deployments. Review before deleting.

**Common causes:**
- Leftover groups from deleted EC2 instances, RDS databases, or ELB deployments
- Test stacks torn down without full cleanup
- Groups created manually but never attached
- CloudFormation stacks deleted leaving orphaned groups

**Required permissions:**
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeNetworkInterfaces`

---

### Storage Waste

#### Unattached EBS Volumes

**Rule ID:** `aws.ebs.volume.unattached`

**What it detects:** EBS volumes not attached to any EC2 instance

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

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

#### Old EBS Snapshots

**Rule ID:** `aws.ebs.snapshot.old`

**What it detects:** Snapshots ≥ 90 days old (default, configurable)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** Age ≥ 90 days (conservative — age alone is a moderate signal)

**Detection logic:**
```python
for snapshot in describe_snapshots(OwnerIds=["self"]):
    age_days = (now - snapshot.StartTime).days
    if age_days >= days_old:  # default 90
        confidence = "MEDIUM"  # age alone is a moderate signal
        risk = "LOW"
```

**Limitations:**
- Does NOT check AMI linkage (by design, avoids false positives)
- Does NOT verify snapshot is unused (conservative approach)

**Common causes:**
- Backup retention policies without lifecycle rules
- Snapshots from deleted volumes
- Over-retention without cleanup

**Required permission:** `ec2:DescribeSnapshots`

---

#### Old AMIs

**Rule ID:** `aws.ec2.ami.old`

**What it detects:** AMIs (Amazon Machine Images) older than 180 days (default threshold)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** Age ≥ 180 days (AMI may still be actively used as template)

**Why MEDIUM confidence:**
- Age alone is a moderate signal
- AMI may be a golden image still used for launches
- Cannot check if AMI is referenced by launch templates or Auto Scaling groups

**Why this matters:**
- AMIs have associated EBS snapshots that incur storage costs
- Old unused AMIs accumulate over time
- Storage costs are ~$0.05/GB-month

**Detection logic:**
```python
for ami in describe_images(Owners=["self"]):
    age_days = (now - ami.creation_date).days
    if age_days >= 180 (default) and ami.state == "available":
        # Flag as old AMI
```

**What gets checked:**
- AMI creation date
- AMI state (only "available" AMIs are flagged)
- Associated snapshot sizes for cost estimation

**Common causes:**
- AMIs from old deployments
- Test/dev AMIs no longer needed
- Superseded golden images
- AMIs from terminated projects

**Cost estimates:**
- Based on total EBS snapshot storage
- ~$0.05/GB-month for snapshot storage
- Example: 100 GB AMI = ~$5/month

**Required permission:** `ec2:DescribeImages`

---

### Network Waste

#### Unattached Elastic IPs

**Rule ID:** `aws.ec2.elastic_ip.unattached`

**What it detects:** Elastic IPs allocated 30+ days ago and currently unattached

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Allocated ≥ 30 days ago and currently unattached (deterministic state)

**Important limitation:**
- AWS does not expose "unattached since" timestamp
- We measure allocation age as a proxy
- An EIP could have been attached until recently (we can't tell)

**Why this matters:**
- Unattached Elastic IPs incur small hourly charges
- State is deterministic (no `AssociationId` means not attached)
- Clear cost optimization signal with zero ambiguity

**Detection logic:**
```python
if "AssociationId" not in eip:  # Not attached
    age_days = (now - eip["AllocationTime"]).days  # Allocation age, NOT unattached duration
    if age_days >= 30:
        confidence = "HIGH"  # Deterministic state: no AssociationId
```

**Common causes:**
- Elastic IPs from terminated EC2 instances
- Reserved IPs for DR that are no longer needed
- Failed deployments leaving orphaned IPs
- Manual allocation without attachment

**Edge cases handled:**
- Classic EIPs without `AllocationTime` are flagged immediately (conservative) and annotated as `is_classic: true` in details
- 30-day threshold avoids false positives from temporary allocations
- Uses allocation age as proxy for unattached duration (unavoidable with AWS API)

**Required permission:** `ec2:DescribeAddresses`

---

#### Detached Network Interfaces (ENIs)

**Rule ID:** `aws.ec2.eni.detached`

**What it detects:** Elastic Network Interfaces (ENIs) currently detached and 60+ days old

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** ENI created ≥ 60 days ago and currently detached

**Important limitation:**
- AWS does not expose "detached since" timestamp
- We measure ENI creation age as a conservative proxy
- An ENI could have been attached until recently (we can't tell)

**Why this matters:**
- Detached ENIs incur small hourly charges
- Often forgotten after failed deployments or incomplete teardowns
- Clear signal with minimal ambiguity

**Detection logic:**
```python
if eni['Status'] == 'available':  # Currently detached
    # Exclude AWS infrastructure using InterfaceType
    if eni['InterfaceType'] not in ['nat_gateway', 'load_balancer', 'vpc_endpoint', ...]:
        age_days = (now - eni['CreateTime']).days  # Creation age, NOT detached duration
        if age_days >= 60:  # Conservative threshold
            confidence = "MEDIUM"  # Medium because we can't measure detached duration
```

**What gets flagged:**
- User-created ENIs (InterfaceType='interface')
- **Lambda/ECS/RDS ENIs** (RequesterManaged=true but YOUR resources!) - explicitly annotated in evidence and details
- Detached ENIs from deleted services

**AWS infrastructure ENIs (excluded):**
- NAT Gateways (InterfaceType='nat_gateway')
- Load Balancers (InterfaceType='load_balancer')
- VPC Endpoints (InterfaceType='vpc_endpoint')
- Gateway Load Balancers

**Key insight:** `RequesterManaged=true` means "AWS created this in YOUR VPC for YOUR resource" — these ARE your responsibility and often waste. RequesterManaged ENIs are included in findings with an explicit evidence signal and `requester_managed: true` in details for downstream filtering.

**Common causes:**
- Failed EC2 instance launches
- Incomplete infrastructure teardown
- Terminated instances with retained ENIs
- Forgotten manual ENI creations

**Edge cases handled:**
- Uses creation age (60+ days) as proxy for detached duration
- 60-day threshold is conservative to reduce false positives
- Could flag ENIs that were attached until recently (unavoidable with AWS API)
- Flags ENIs without tags (ownership unclear signal)
- `interface_type` and `requester_managed` included in details for CI/CD filtering

**Why 60 days (not 30):**
- We measure creation age, not detached duration
- Longer threshold reduces false positives
- If an ENI is 60+ days old and currently detached, it's worth reviewing

**Required permission:** `ec2:DescribeNetworkInterfaces`

---

#### Idle NAT Gateways

**Rule ID:** `aws.ec2.nat_gateway.idle`

**What it detects:** NAT Gateways with zero traffic for 14+ days (default, configurable)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** No traffic detected for 14+ days (CloudWatch metrics checked, but seasonal patterns not verified)

**Why MEDIUM confidence:**
- Zero traffic is a strong signal, but gateway may be for DR/standby
- Cannot verify planned future usage or blue/green deployments
- Seasonal traffic patterns not checked

**Why this matters:**
- NAT Gateways cost ~$0.045/hour + $0.045/GB data processing (~$32/month base)
- Idle gateways are a clear cost optimization signal
- Common after VPC restructuring or service migrations

**Detection logic:**
```python
for gw in describe_nat_gateways():
    if gw.state == "available" and age >= idle_threshold_days:
        # Check CloudWatch metrics for traffic
        bytes_out = get_metric(BytesOutToDestination, period=idle_threshold_days)
        bytes_in = get_metric(BytesInFromSource, period=idle_threshold_days)
        if bytes_out == 0 and bytes_in == 0:
            confidence = "MEDIUM"
```

**CloudWatch metrics checked:**
- `AWS/NATGateway` → `BytesOutToDestination` (daily sum)
- `AWS/NATGateway` → `BytesInFromSource` (daily sum)

**Common causes:**
- VPC restructuring leaving orphaned NAT Gateways
- Service migrations to different subnets/VPCs
- Dev/staging environments with no active workloads
- DR standby gateways (intentional, but worth reviewing)

**Cost estimates:**
- ~$32/month base cost per idle NAT Gateway
- Additional $0.045/GB data processing when active

**Required permissions:**
- `ec2:DescribeNatGateways`
- `cloudwatch:GetMetricStatistics`

---

#### Idle Elastic Load Balancers (ALB/CLB/NLB)

**Rule IDs:**
- `aws.elbv2.alb.idle` — Application Load Balancer
- `aws.elbv2.nlb.idle` — Network Load Balancer
- `aws.elb.clb.idle` — Classic Load Balancer

**What it detects:** Load balancers with zero traffic for 14+ days (default, configurable)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Zero traffic AND no registered targets/instances
- **MEDIUM:** Zero traffic only (targets/instances may still be registered)

**Risk:** MEDIUM

**Why this matters:**
- ELBs incur base hourly charges regardless of traffic (~$16-22/month)
- Idle load balancers are a clear cost optimization signal
- Common after service migrations or decommissions

**Detection logic:**
```python
# ALB/NLB (elbv2)
for lb in describe_load_balancers():
    if age >= idle_threshold_days:
        traffic = get_metric(RequestCount or NewFlowCount, period=idle_threshold_days)
        has_targets = check_target_groups(lb)
        if traffic == 0:
            confidence = "HIGH" if not has_targets else "MEDIUM"

# CLB (elb)
for lb in describe_load_balancers():
    if age >= idle_threshold_days:
        traffic = get_metric(RequestCount, period=idle_threshold_days)
        has_instances = len(lb.instances) > 0
        if traffic == 0:
            confidence = "HIGH" if not has_instances else "MEDIUM"
```

**CloudWatch metrics checked:**
- `AWS/ApplicationELB` → `RequestCount` (ALB, daily sum)
- `AWS/NetworkELB` → `NewFlowCount` (NLB, daily sum)
- `AWS/ELB` → `RequestCount` (CLB, daily sum)

**Exclusions:**
- LBs younger than the idle threshold

**Common causes:**
- Service migrations leaving orphaned load balancers
- Dev/staging environments with no active workloads
- Decommissioned applications with retained infrastructure
- Blue/green deployments with stale LBs

**Cost estimates:**
- ~$16-22/month base cost per idle load balancer (region dependent)

**Required permissions:**
- `elasticloadbalancing:DescribeLoadBalancers`
- `elasticloadbalancing:DescribeTargetGroups`
- `elasticloadbalancing:DescribeTargetHealth`
- `cloudwatch:GetMetricStatistics`

---

### Platform Waste

#### Idle RDS Instances

**Rule ID:** `aws.rds.instance.idle`

**What it detects:** RDS instances with zero database connections for 14+ days (default, configurable)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Zero connections for 14+ days (CloudWatch metrics checked, strong idle signal)

**Why HIGH confidence:**
- Zero database connections is a very strong signal of non-use
- Combined with age check and tag exclusions, false positive rate is low

**Risk:** HIGH

**Why HIGH risk:**
- RDS instances are among the more expensive AWS resources
- Even small instances cost $12-50+/month
- Production-class instances can cost $100-700+/month

**Why this matters:**
- RDS instances incur hourly charges regardless of usage
- Idle instances with no connections are a clear cost optimization signal
- Common after application migrations or decommissions

**Detection logic:**
```python
for instance in describe_db_instances():
    if instance.status == "available" and age >= idle_threshold_days:
        if not instance.read_replica_source:  # Skip read replicas
            connections = get_metric(DatabaseConnections, period=idle_threshold_days)
            if connections == 0:
                confidence = "HIGH"
                risk = "HIGH"
```

**CloudWatch metrics checked:**
- `AWS/RDS` -> `DatabaseConnections` (daily sum)

**Exclusions:**
- Aurora cluster members (`DBClusterIdentifier` set) — Aurora instances are managed at cluster level and may show zero connections individually even when the cluster is active
- Read replicas (`ReadReplicaSourceDBInstanceIdentifier` set)
- Instances younger than the idle threshold

**Common causes:**
- Applications migrated to different databases
- Dev/staging instances left running
- Decommissioned services with retained databases
- Test databases no longer needed

**Required permissions:**
- `rds:DescribeDBInstances`
- `cloudwatch:GetMetricStatistics`

---

#### Old Manual RDS Snapshots

**Rule ID:** `aws.rds.snapshot.old`

**What it detects:** Manual RDS snapshots older than 90 days (default, configurable)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Snapshot age is known and exceeds threshold (deterministic)

**Risk:** LOW

**Why this matters:**
- Manual RDS snapshots are retained indefinitely until explicitly deleted
- Storage charges accrue at ~$0.095/GB-month regardless of whether the source DB still exists
- Snapshots older than 90 days are rarely needed for active recovery

**Detection logic:**
```python
for snapshot in describe_db_snapshots(SnapshotType="manual"):
    if snapshot.status == "available":
        age_days = (now - snapshot.create_time).days
        if age_days >= days_old:
            confidence = "HIGH"
            risk = "LOW"
```

**Exclusions:**
- Automated snapshots (`SnapshotType=automated`) — managed by RDS retention policy, auto-deleted
- Snapshots in non-`available` states

**Common causes:**
- Pre-migration snapshots never cleaned up
- Manual backups taken before schema changes and forgotten
- Snapshots of deleted databases retained for compliance but past their useful life

**Cost estimate:** ~$0.095/GB-month based on `AllocatedStorage` (the provisioned DB size). RDS snapshots are incremental so actual storage used may be lower — treat this as a ceiling estimate, not an exact figure.

**Required permissions:**
- `rds:DescribeDBSnapshots`

---

### Observability Waste

#### CloudWatch Log Groups (Infinite Retention)

**Rule ID:** `aws.cloudwatch.logs.infinite_retention`

**What it detects:** Log groups with no retention policy (never expires)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** No retention policy configured

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

### Governance

#### Untagged Resources

**Rule ID:** `aws.resource.untagged`

**What it detects:** Resources with zero tags

**Resources checked:**
- EBS volumes
- S3 buckets
- CloudWatch log groups

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** Zero tags (always MEDIUM, never HIGH)

**Why this matters:**
- Ownership ambiguity
- Compliance violations (SOC2, ISO27001)
- Cleanup decision paralysis

**Required permissions:**
- `ec2:DescribeVolumes`
- `s3:ListAllMyBuckets`
- `s3:GetBucketTagging`
- `logs:DescribeLogGroups`

### AI/ML Waste

#### Idle SageMaker Endpoints

**Rule ID:** `aws.sagemaker.endpoint.idle`

**Category:** `ai`

**What it detects:** SageMaker inference endpoints in `InService` state with zero invocations over 14+ days. GPU-backed endpoints (`ml.g4dn`, `ml.g5`, `ml.p3`, `ml.p4d`, `ml.p5`, Inferentia, Trainium) are flagged as HIGH risk due to significantly higher hourly cost.

**Confidence:**
- **HIGH:** Zero invocations for the full 14-day window (endpoint age ≥ 14 days)
- **MEDIUM:** Zero invocations but endpoint is 7–13 days old

**Risk:**
- **HIGH:** GPU/accelerator-backed instance (`ml.g4dn.*`, `ml.g5.*`, `ml.p3.*`, `ml.p4d.*`, etc.)
- **MEDIUM:** CPU-backed instance

**Why this matters:**
- SageMaker endpoints accrue charges continuously while `InService`, regardless of traffic
- GPU-backed endpoints cost $500–$23K/month depending on instance type
- Endpoints deployed for experiments or demos are frequently abandoned after initial testing
- Multi-variant endpoints multiply the cost per variant

**Estimated monthly cost:**
- `ml.g4dn.xlarge` — ~$531/month
- `ml.g5.xlarge` — ~$600/month
- `ml.p3.2xlarge` — ~$2,754/month
- `ml.p4d.24xlarge` — ~$23,596/month
- `ml.p4de.24xlarge` — ~$29,908/month
- `ml.p5.48xlarge` — ~$71,774/month
- `ml.m5.xlarge` — ~$188/month

**Required permissions:**
- `sagemaker:ListEndpoints`
- `sagemaker:DescribeEndpoint`
- `sagemaker:DescribeEndpointConfig`
- `cloudwatch:GetMetricStatistics`

> **Not run by default.** AI/ML rules are opt-in to avoid surprising users who don't use these services. Run with `cleancloud scan --provider aws --category ai` (or `--category all` to combine with hygiene rules). If the permissions above are not granted, the rule is gracefully skipped and reported in the skipped rules section — it will not fail the scan. Attach [`security/aws/ai-readonly.json`](../security/aws/ai-readonly.json) to your IAM role to enable this rule.

---

#### Idle SageMaker Notebook Instances

**Rule ID:** `aws.sagemaker.notebook.idle`

**Category:** `ai`

**What it detects:** SageMaker Notebook Instances in `InService` state with no control-plane activity for 14+ days, detected via `LastModifiedTime` from the SageMaker control plane. GPU-backed notebooks (`ml.g4dn`, `ml.g5`, `ml.p3`, `ml.p4d`, `ml.p4de`, `ml.p5`, Inferentia, Trainium) idle for 2× the threshold are escalated to CRITICAL. Data scientists frequently leave notebook instances running between sprints, after project handovers, or when granted a new instance without stopping the old one.

**Detection signal — why `LastModifiedTime`:**
SageMaker Notebook Instances do not publish utilisation metrics to CloudWatch by default (unlike endpoints, which emit `Invocations`). `LastModifiedTime` is updated by SageMaker when the notebook configuration changes, when the instance is stopped and restarted, or when a linked Git repository is synced. A notebook with `LastModifiedTime` older than the idle threshold has had no control-plane activity — this is the correct and standard signal used by AWS Cost Optimisation Hub for notebook idle detection.

**Confidence:**
- **HIGH:** `LastModifiedTime` ≥ 14 days ago AND notebook age ≥ 14 days
- **MEDIUM:** `LastModifiedTime` ≥ 10 days ago (75% of threshold) AND notebook age ≥ 10 days

**Risk:**
- **CRITICAL:** GPU/accelerator-backed instance AND `idle_ratio ≥ 2.0` (idle for 2× the threshold, e.g. 28+ days at the default 14-day window)
- **HIGH:** GPU/accelerator-backed instance (`ml.g4dn.*`, `ml.g5.*`, `ml.p3.*`, `ml.p4d.*`, `ml.p4de.*`, `ml.p5.*`, Inferentia, Trainium)
- **MEDIUM:** CPU-backed instance

**Why this matters:**
- Notebook Instances bill continuously while `InService`, regardless of whether any kernels are running
- GPU-backed notebooks cost $500–$71K+/month depending on instance type (ml.p5.48xlarge: ~$71,774/month)
- Notebooks are commonly left running after a sprint ends, a project is deprioritised, or a team member leaves
- Unlike endpoints, notebooks have no auto-scaling — an idle `ml.p3.8xlarge` at $11K/month runs indefinitely unless explicitly stopped

**Estimated monthly cost:**
- `ml.t3.medium` — ~$42/month
- `ml.m5.xlarge` — ~$188/month
- `ml.g4dn.xlarge` — ~$531/month
- `ml.g5.xlarge` — ~$600/month
- `ml.p3.2xlarge` — ~$2,754/month
- `ml.p3.8xlarge` — ~$11,016/month
- `ml.p4d.24xlarge` — ~$23,596/month
- `ml.p4de.24xlarge` — ~$29,908/month
- `ml.p5.48xlarge` — ~$71,774/month

**Required permissions:**
- `sagemaker:ListNotebookInstances`
- `sagemaker:DescribeNotebookInstance`

> **Not run by default.** AI/ML rules are opt-in to avoid surprising users who don't use these services. Run with `cleancloud scan --provider aws --category ai` (or `--category all` to combine with hygiene rules). If the permissions above are not granted, the rule is gracefully skipped and reported in the skipped rules section — it will not fail the scan. Attach [`security/aws/ai-readonly.json`](../security/aws/ai-readonly.json) to your IAM role to enable this rule.

---

#### Idle Azure ML Compute Clusters

**Rule ID:** `azure.aml.compute.idle`

**Category:** `ai`

**What it detects:** Azure Machine Learning compute clusters (`AmlCompute`) with `min_node_count > 0` and zero active nodes over 14+ days. Clusters configured with a non-zero minimum keep instances running continuously regardless of job activity — identical billing model to SageMaker InService endpoints. GPU clusters (NC/ND/NV series) cost $600–$15K/month at minimum node count.

**Confidence:**
- **HIGH:** Zero active nodes for the full 14-day window (cluster age ≥ 14 days)
- **MEDIUM:** Zero active nodes, cluster age is 7–13 days, or cluster creation time unavailable

**Risk:**
- **HIGH:** GPU-backed VM size (`Standard_NC*`, `Standard_ND*`, `Standard_NV*`)
- **MEDIUM:** CPU-backed VM size

**Why this matters:**
- `min_node_count > 0` means instances are always running, always billed — even with no jobs submitted
- GPU clusters cost $600–$15K/month per node at minimum capacity
- Clusters are frequently created for experiments or training runs and left with non-zero minimums for "warm-start convenience"

**Metric strategy:** Queries Azure Monitor `Active Nodes` metric (with `ComputeName` dimension filter). Falls back to `NodeCount` and `CurrentNodeCount` if the primary metric is unavailable. Only dimension-filtered metrics are used to confirm idle — workspace-level unfiltered queries cannot safely confirm individual cluster state.

**Estimated monthly cost (per node at `min_node_count`):**
- `Standard_NC6` — ~$648/month
- `Standard_NC12` — ~$1,296/month
- `Standard_NC6s_v3` — ~$2,203/month
- `Standard_ND40rs_v2` — ~$15,862/month
- `Standard_D4_v2` — ~$259/month

**Required permissions:**
- `Microsoft.MachineLearningServices/workspaces/read`
- `Microsoft.MachineLearningServices/workspaces/computes/read`
- `Microsoft.Insights/metrics/read`

> **Not run by default.** Run with `cleancloud scan --provider azure --category ai` (or `--category all`). Add `Microsoft.MachineLearningServices/workspaces/read` and `Microsoft.MachineLearningServices/workspaces/computes/read` to your custom role or use the built-in `AzureML Data Scientist` role in read-only mode.

---

#### Idle Azure ML Compute Instances

**Rule ID:** `azure.ml.compute_instance.idle`

**Category:** `ai`

**What it detects:** Azure ML Compute Instances in `Running` state with no control-plane activity for 14+ days, detected via `last_operation.operation_time`. Compute Instances are single-VM interactive development environments (Jupyter, VS Code, RStudio) that bill continuously while Running — regardless of kernel activity. GPU instances (NC/ND/NV series) idle for 2× the threshold are escalated to CRITICAL.

**Detection signal — why `last_operation`:**
Azure ML Compute Instances do not publish per-instance utilisation metrics to Azure Monitor by default. `last_operation.operation_time` is updated by the Azure ML control plane on Start, Stop, Restart, and Create operations. An instance with no recent operation has had no control-plane activity — the same approach used for SageMaker Notebook `LastModifiedTime`. Falls back to `system_data.last_modified_at` if `last_operation` is unavailable.

**Confidence:**
- **HIGH:** `last_operation.operation_time` or `last_modified_at` signal ≥ 14 days ago AND instance age ≥ 14 days
- **MEDIUM:** ≥ 75% of threshold on both signals, OR age-only fallback (when neither `last_operation` nor `last_modified_at` is available — age alone is not evidence of idleness)

**Risk:**
- **CRITICAL:** GPU instance AND `idle_ratio ≥ 2.0` (e.g. 28+ days at the default 14-day window)
- **HIGH:** GPU instance (`Standard_NC*`, `Standard_ND*`, `Standard_NV*`)
- **MEDIUM:** CPU instance

**Why this matters:**
- Compute Instances bill at the full VM rate while Running — a stopped instance costs nothing
- GPU instances cost $600–$15K+/month running continuously
- Data scientists frequently leave instances Running after finishing a sprint, switching to a new instance, or during holidays

**Estimated monthly cost:**
- `Standard_DS3_v2` — ~$260/month
- `Standard_NC6s_v3` — ~$2,203/month
- `Standard_NC24s_v3` — ~$8,812/month
- `Standard_ND40rs_v2` — ~$15,862/month

**Required permissions:**
- `Microsoft.MachineLearningServices/workspaces/read`
- `Microsoft.MachineLearningServices/workspaces/computes/read`

> **Not run by default.** Run with `cleancloud scan --provider azure --category ai`. Attach `security/azure/ai-readonly-role.json` to your service principal to enable this rule.

---

## Azure Rules

### Compute Waste

#### Stopped (Not Deallocated) VMs

**Rule ID:** `azure.vm.stopped_not_deallocated`

**What it detects:** VMs in 'Stopped' state (OS-level shutdown) that are not deallocated, still incurring full compute charges

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Power state is 'Stopped' (deterministic state check, zero false positives)

**Risk:** HIGH

**Why HIGH risk:**
- Stopped-but-not-deallocated VMs incur full compute charges ($30-500+/month depending on SKU)
- Users often believe their VM is "off" but are paying full price
- Classic Azure cost trap with significant financial impact

**Why this matters:**
- Azure distinguishes between 'Stopped' (OS shutdown) and 'Deallocated' (compute released)
- Only deallocated VMs stop incurring compute charges
- 100% deterministic state check with zero false positives

**Detection logic:**
```python
for vm in virtual_machines.list_all():
    instance_view = virtual_machines.instance_view(resource_group, vm.name)
    power_state = get_power_state(instance_view.statuses)  # PowerState/* code
    if power_state == "PowerState/stopped":
        confidence = "HIGH"  # Deterministic: stopped but not deallocated
        risk = "HIGH"  # Full compute charges still applied
```

**Power states:**
- `PowerState/running` — active, skip
- `PowerState/deallocated` — properly stopped, skip
- `PowerState/stopped` — **FLAGGED** (still incurring compute charges)
- `PowerState/starting`, `PowerState/stopping`, `PowerState/deallocating` — transitional, skip

**Common causes:**
- Shutting down the VM from inside the OS (instead of Azure portal/CLI)
- Using `Stop-AzVM` without `-StayProvisioned false`
- RDP/SSH shutdown commands
- Automated scripts that stop but don't deallocate

**Required permission:** `Microsoft.Compute/virtualMachines/read`

---

### Storage Waste

#### Unattached Managed Disks

**Rule ID:** `azure.compute.disk.unattached`

**What it detects:** Managed disks not attached to any VM

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** Unattached ≥ 7 days (conservative for all ages — unattached state is deterministic but attachment intent is not)
- Not flagged: < 7 days

**Detection logic:**
```python
for disk in disks.list():
    if disk.managed_by is not None:
        continue  # attached to a VM
    age_days = (now - disk.time_created).days
    if age_days >= 7:
        confidence = "MEDIUM"  # conservative regardless of age
    else:
        continue  # too new to flag
```

**Common causes:**
- Disks from deleted VMs
- Failed deployments
- Autoscaling cleanup gaps

**Required permission:** `Microsoft.Compute/disks/read`

---

#### Old Managed Disk Snapshots

**Rule ID:** `azure.compute.snapshot.old`

**What it detects:** Snapshots older than configured thresholds

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** Age ≥ 30 days (conservative for all ages — age alone is a moderate signal)
- Not flagged: < 30 days

**Detection logic:**
```python
for snapshot in snapshots.list():
    age_days = (now - snapshot.time_created).days
    if age_days >= 90:
        confidence = "MEDIUM"  # conservative even at high age
    elif age_days >= 30:
        confidence = "MEDIUM"
    else:
        continue  # too new to flag
```

**Limitations:**
- Does NOT check if snapshot is referenced by images
- Conservative to avoid false positives

**Common causes:**
- Snapshots from backup jobs
- Over-retention without lifecycle policies
- Snapshots from deleted disks

**Required permission:** `Microsoft.Compute/snapshots/read`

---

### Network Waste

#### Unused Public IP Addresses

**Rule ID:** `azure.network.public_ip.unused`

**What it detects:** Public IPs not attached to any network interface

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** Not attached (deterministic state, but may be reserved intentionally)

**Why this matters:**
- Public IPs incur charges even when unused
- State is deterministic (no heuristics needed)

**Detection logic:**
```python
if public_ip.ip_configuration is None:
    confidence = "MEDIUM"
```

**Required permission:** `Microsoft.Network/publicIPAddresses/read`

---

#### Standard Load Balancer with No Backend Members

**Rule ID:** `azure.load_balancer.no_backends`

**What it detects:** Standard Load Balancers where all backend pools have zero members

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Standard SKU with zero backend members across all pools (deterministic state)

**Excluded:**
- Basic SKU load balancers are skipped (retired, no cost signal)

**Why this matters:**
- Standard Load Balancers incur base charges (~$18/month) regardless of backends
- Empty LBs are a clear cost optimization signal
- Common after VM/VMSS teardowns or migrations

**Detection logic:**
```python
if lb.sku.name == "Standard":
    pools = lb.backend_address_pools or []
    # Check both NIC-based and IP-based backend representations
    has_members = any(
        pool.backend_ip_configurations or pool.load_balancer_backend_addresses
        for pool in pools
    )
    if not has_members:
        confidence = "HIGH"  # Deterministic: zero members across all pools
```

**Backend representations checked:**
- `backend_ip_configurations` — NIC-based backends (standard VMs)
- `load_balancer_backend_addresses` — IP-based backends (Private Link, hybrid)

**Common causes:**
- VMs or VMSS deleted but LB retained
- Migration from Basic to Standard leaving empty LBs
- Failed deployments or incomplete teardowns
- Hub-spoke architecture cleanup gaps

**Required permission:** `Microsoft.Network/loadBalancers/read`

---

#### Application Gateway with No Backend Targets

**Rule ID:** `azure.application_gateway.no_backends`

**What it detects:** Application Gateways where all backend pools have zero targets (no IP addresses or FQDNs)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** All backend pools have zero targets (deterministic state)

**Excluded:**
- Gateways with `provisioning_state != "Succeeded"` are skipped (in-progress)

**Why this matters:**
- Application Gateways incur significant charges regardless of backends
- Standard_v2 and WAF_v2 SKUs cost $150-300+/month
- Empty gateways are a clear cost optimization signal

**Detection logic:**
```python
for gw in application_gateways:
    pools = gw.backend_address_pools or []
    has_any_targets = any(
        (pool.backend_addresses and len(pool.backend_addresses) > 0) or
        (pool.backend_ip_configurations and len(pool.backend_ip_configurations) > 0)
        for pool in pools
    )
    if not has_any_targets:
        confidence = "HIGH"  # Deterministic: zero targets across all pools
        risk = "MEDIUM"  # Significant cost impact ($150-300+/month)
```

**Backend targets checked:**
- `backend_addresses` array (IP addresses or FQDNs)
- `backend_ip_configurations` array (NIC-based backend references)

**Common causes:**
- Backend VMs or services deleted but gateway retained
- Migration or transition leaving empty gateways
- Failed deployments or incomplete teardowns
- WAF-only setup without actual backends (rare)

**Cost estimates by SKU:**
- Standard_v2, WAF_v2: $150-300+/month
- Standard, WAF (v1): $20-50/month

**Required permission:** `Microsoft.Network/applicationGateways/read`

---

#### Idle VNet Gateways (VPN/ExpressRoute)

**Rule ID:** `azure.virtual_network_gateway.idle`

**What it detects:** VPN Gateways and ExpressRoute Gateways with no active connections

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** No active connections (connection state checked, but P2S clients not verified)

**Why MEDIUM confidence:**
- We can verify Site-to-Site and ExpressRoute connections
- Point-to-Site VPN client count requires additional API calls
- Gateway may have P2S config but no way to check active clients without deeper inspection

**Risk:** HIGH

**Why HIGH risk:**
- VNet Gateways are among the most expensive idle resources ($500-3,500+/month)
- Cost impact is material even for a single idle gateway
- Significantly higher than Load Balancers (~$18/month) or App Gateways (~$150-300/month)

**Why this matters:**
- VNet Gateways incur significant charges regardless of connections
- VPN Gateway SKUs: $27-3,500+/month depending on SKU
- ExpressRoute Gateway SKUs: $125-1,100+/month
- Idle gateways are a major cost optimization signal

**Detection logic:**
```python
for gw in virtual_network_gateways:
    connections = list_connections(gw)
    active_connections = [c for c in connections if c.connection_status == "Connected"]

    if gw.gateway_type == "Vpn":
        if len(active_connections) == 0 and not has_p2s_config:
            # Flag as idle
    elif gw.gateway_type == "ExpressRoute":
        if len(active_connections) == 0:
            # Flag as idle
```

**Connection states checked:**
- Site-to-Site VPN connections (connection_status == "Connected")
- ExpressRoute circuit connections
- Point-to-Site VPN configuration (presence only, not active client count)

**Common causes:**
- VPN tunnels torn down but gateway retained
- ExpressRoute circuits decommissioned
- Test/dev gateways left running
- Migration or transition leaving orphaned gateways
- DR standby gateways (intentional, but worth reviewing)

**Cost estimates by SKU:**
- Basic: $27/month
- VpnGw1/ErGw1AZ: $140-195/month
- VpnGw2/ErGw2AZ: $360-505/month
- VpnGw3/ErGw3AZ: $930-1,115/month
- HighPerformance/UltraPerformance: $335-670/month

**Required permissions:**
- `Microsoft.Network/virtualNetworkGateways/read`
- `Microsoft.Network/connections/read`

---

### Platform Waste

#### Empty App Service Plans

**Rule ID:** `azure.app_service_plan.empty`

**What it detects:** Paid App Service Plans with zero hosted apps (`number_of_sites == 0`)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Paid tier plan with 0 apps (deterministic state)

**Excluded tiers:**
- Free and Shared tiers are skipped (no cost signal)

**Why this matters:**
- Paid App Service Plans incur charges regardless of hosted apps
- Empty plans are a clear cost optimization signal
- Common after app deletions or failed deployments

**Detection logic:**
```python
if plan.number_of_sites == 0:
    if plan.sku.tier not in ("Free", "Shared"):
        confidence = "HIGH"  # Deterministic: zero apps on paid plan
```

**Common causes:**
- Apps deleted but plan retained
- Failed deployments leaving empty plans
- Scaling plans created but never used
- Migration leaving old plans behind

**Required permissions:** `Microsoft.Web/serverfarms/read`, `Microsoft.Web/serverfarms/sites/read`

---

#### Idle Azure SQL Databases

**Rule ID:** `azure.sql.database.idle`

**What it detects:** Azure SQL databases with zero connections for 14+ days (default, configurable)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Zero connections for 14+ days (Azure Monitor metrics checked, strong idle signal)

**Risk:** HIGH

**Why HIGH risk:**
- Azure SQL databases in Standard/Premium tiers cost $15-$7,500+/month
- Idle databases with no connections are a clear cost optimization signal

**Why this matters:**
- Azure SQL databases incur charges regardless of usage
- Standard and Premium tiers have significant hourly costs
- Idle databases are a major cost optimization opportunity

**Detection logic:**
```python
for server in sql_servers:
    for db in databases.list_by_server(rg, server.name):
        if db.name == "master":  # Skip system databases
            continue
        if db.sku.tier == "Basic":  # Skip Basic tier (< $5/month)
            continue
        connections = get_metric(connection_successful, period=14_days)
        if connections == 0:
            confidence = "HIGH"
            risk = "HIGH"
```

**Azure Monitor metrics checked:**
- `connection_successful` (daily total over 14-day window)

**Exclusions:**
- System databases (`master`)
- Basic tier databases (< $5/month, not worth flagging)

**Common causes:**
- Applications migrated to different databases
- Dev/staging databases left running
- Decommissioned services with retained databases
- Test databases no longer needed

**Cost estimates by SKU:**
- Standard S0: ~$15/month
- Standard S3: ~$150/month
- Premium P1: ~$465/month
- Premium P6: ~$3,720/month
- Premium P15: ~$7,446/month

**Required permissions:**
- `Microsoft.Sql/servers/read`
- `Microsoft.Sql/servers/databases/read`
- `Microsoft.Insights/metrics/read`

---

#### Idle App Services

**Rule ID:** `azure.app_service.idle`

**What it detects:** Running App Service web apps with zero HTTP requests for 14+ days on paid plans

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Zero requests for 14+ days (Azure Monitor `Requests` metric, strong idle signal)

**Risk:** MEDIUM

**Why this matters:**
- App Service Plans on paid tiers bill compute charges continuously regardless of traffic
- An app with zero requests for 14+ days is a strong signal of abandonment
- Common for dev/staging apps that were never decommissioned

**Detection logic:**
```python
for app in web_apps.list():
    if app.state == "Running" and app.sku.tier not in ("Free", "Shared", "Dynamic"):
        requests = monitor.metrics("Requests", period=days_idle)
        if requests == 0:
            confidence = "HIGH"
            risk = "MEDIUM"
```

**Excluded tiers:**
- Free, Shared, Dynamic (Consumption/serverless) — no meaningful idle cost

**Common causes:**
- Dev or staging apps left running after project end
- Feature branches deployed and never torn down
- Apps migrated to containers but old App Service not removed

**Cost estimates by tier (single instance):**
- Basic: ~$55/month
- Standard: ~$73/month
- Premium/PremiumV2/V3: ~$146/month
- Isolated/IsolatedV2: ~$298/month

Cost assumes one instance. Scaled-out plans (multiple instances) will cost proportionally more — treat these as minimum estimates.

**Not detected:**
- Non-HTTP workloads such as WebJobs or background services with no inbound HTTP traffic — these produce zero `Requests` metric data even when active. Review before deleting.

**Required permissions:**
- `Microsoft.Web/sites/read`
- `Microsoft.Web/serverfarms/read`
- `Microsoft.Insights/metrics/read`

---

#### Unused Container Registries

**Rule ID:** `azure.container_registry.unused`

**What it detects:** Container registries with zero image pulls for 90+ days (default, configurable)

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **HIGH:** Zero successful pulls AND zero successful pushes for 90+ days (Azure Monitor `SuccessfulPullCount` and `SuccessfulPushCount` metrics)

**Risk:** LOW

**Why this matters:**
- Container registries accrue storage and per-operation charges regardless of usage
- A registry with no pulls and no pushes for 90+ days signals complete abandonment
- Common after workload migrations to other registries or container platforms

**Detection logic:**
```python
for registry in registries.list():
    if registry.provisioning_state == "Succeeded":
        pulls = monitor.metrics("SuccessfulPullCount", period=days_unused)
        pushes = monitor.metrics("SuccessfulPushCount", period=days_unused)
        if pulls == 0 and pushes == 0:
            confidence = "HIGH"
            risk = "LOW"
```

Registries with active push activity (e.g. CI pipelines writing images) but zero pulls are **not** flagged — they are in active use.

**Common causes:**
- Workloads migrated to another registry (e.g., Docker Hub → ACR → GHCR)
- Projects retired without cleaning up the registry
- Old build artifacts never consumed by any deployment

**Cost estimates by SKU (base fee only):**
- Basic: ~$5/month + storage
- Standard: ~$20/month + storage
- Premium: ~$50/month + storage

These are floor estimates. ACR also charges per GB of stored images (~$0.003/GB-day). For registries with large image layers, storage can exceed the base fee — actual cost may be significantly higher.

**Required permissions:**
- `Microsoft.ContainerRegistry/registries/read`
- `Microsoft.Insights/metrics/read`

---

### Governance

#### Untagged Resources

**Rule ID:** `azure.resource.untagged`

**What it detects:** Resources with zero tags

**Resources checked:**
- Managed disks (7+ days old)
- Snapshots

**Confidence:**

Confidence thresholds and signal weighting are documented in [confidence.md](confidence.md).

- **MEDIUM:** Untagged disk that's also unattached
- **LOW:** Untagged snapshot or attached disk

**Required permissions:**
- `Microsoft.Compute/disks/read`
- `Microsoft.Compute/snapshots/read`

---

## GCP Rules

### Compute Waste

#### Stopped VM Instances

**Rule ID:** `gcp.compute.vm.stopped`

**What it detects:** VM instances in `TERMINATED` state for 30+ days

**Confidence:**

- **HIGH:** `lastStopTimestamp` present and ≥ 30 days ago (deterministic timestamp)
- **MEDIUM:** `lastStopTimestamp` absent — instance is TERMINATED but stop time is unavailable
- Not flagged: stopped < 30 days, or instance in any other state (RUNNING, STAGING, etc.)

**Risk:** LOW

**Why this matters:**
- A TERMINATED GCP VM does not charge for vCPU or memory — but every attached Persistent Disk accrues storage charges at ~$0.04/GB-month (standard) or ~$0.17/GB-month (SSD), regardless of instance state
- A 500 GB root disk on a forgotten stopped instance costs ~$20/month indefinitely
- This is the GCP equivalent of a stopped EC2 instance — the compute is free, the storage is not

**Detection logic:**
```python
for instance in instances_client.aggregated_list(project=project_id):
    if instance.status == "TERMINATED":
        if _parse_gcp_timestamp(instance.last_stop_timestamp) > cutoff:
            flag(instance)
```

**Cost estimate:** Sum of attached PERSISTENT disk sizes × $0.04/GB/month (SCRATCH disks excluded — they are ephemeral)

**Required permissions:**
- `compute.instances.list` (included in `roles/compute.viewer`)

---

### Storage Waste

#### Unattached Persistent Disks

**Rule ID:** `gcp.compute.disk.unattached`

**What it detects:** Persistent Disks in `READY` state with no attached VM (`users == []`)

**Confidence:**

- **HIGH:** Disk is READY and has no users — unambiguous detachment

**Risk:** LOW

**Why this matters:**
- GCP charges for Persistent Disks regardless of whether they are attached to a VM
- pd-standard: ~$0.04/GB/month, pd-ssd: ~$0.17/GB/month, pd-balanced: ~$0.10/GB/month, pd-extreme: ~$0.12/GB/month
- Unattached disks accumulate when VMs are deleted without deleting their disks — the most common source of GCP storage waste
- A 500 GB pd-ssd left unattached costs ~$85/month

**Detection logic:**
```python
for disk in disks_client.aggregated_list(project=project_id):
    if disk.status == "READY" and not disk.users:
        flag(disk)
```

**Cost estimate by disk type:**

| Type | Rate |
|---|---|
| `pd-standard` | $0.04/GB/month |
| `pd-balanced` | $0.10/GB/month |
| `pd-ssd` | $0.17/GB/month |
| `pd-extreme` | $0.12/GB/month |

**Required permissions:**
- `compute.disks.list` (included in `roles/compute.viewer`)

---

#### Old Disk Snapshots

**Rule ID:** `gcp.compute.snapshot.old`

**What it detects:** Disk snapshots older than 90 days

**Confidence:**

- **HIGH:** Source disk no longer exists (snapshot is orphaned — the source was deleted)
- **MEDIUM:** Source disk still exists (might be intentional long-term backup or DR snapshot)

**Risk:** LOW

**Why this matters:**
- GCP snapshots are billed at ~$0.026/GB/month compressed storage in Cloud Storage
- Automated snapshot policies are frequently removed while their snapshots are left behind
- One-off manual snapshots are rarely cleaned up — they persist indefinitely until explicitly deleted
- Snapshots are global resources — they accumulate across all zones and appear in no specific region

**Detection logic:**
```python
for snapshot in snapshots_client.list(project=project_id):
    if snapshot.status == "READY":
        if _parse_gcp_timestamp(snapshot.creation_timestamp) < cutoff:
            confidence = HIGH if not snapshot.source_disk else MEDIUM
            flag(snapshot)
```

**Cost estimate:** Uses `storage_bytes` (actual compressed size) when available; falls back to `disk_size_gb × $0.026/GB/month`

Note: `region_filter` is ignored for snapshots — GCP snapshots are global resources with no region attribute.

**Required permissions:**
- `compute.snapshots.list` (included in `roles/compute.viewer`)

---

### Network Waste

#### Unused Reserved Static IPs

**Rule ID:** `gcp.compute.ip.unused`

**What it detects:** Reserved static IP addresses (regional and global) in `RESERVED` status (not `IN_USE`)

**Confidence:**

- **HIGH:** IP status is `RESERVED` — unambiguous, GCP itself confirms it is not attached

**Risk:** LOW

**Why this matters:**
- GCP bills ~$0.01/hour (~$7.20/month) for each static IP in RESERVED status under the PREMIUM network tier
- Reserved IPs accumulate when VMs, load balancers, or NAT gateways are deleted without releasing their IPs
- Unlike ephemeral IPs, reserved IPs persist independently — they must be explicitly released to stop billing

**Detection logic:**
```python
# Regional IPs
for address in addresses_client.aggregated_list(project=project_id):
    if address.status == "RESERVED":
        flag(address, scope="regional")

# Global IPs (skipped if region_filter is set)
for address in global_addresses_client.list(project=project_id):
    if address.status == "RESERVED":
        flag(address, scope="global")
```

**Graceful degradation:** If `compute.globalAddresses.list` is denied but regional IPs succeed, the rule returns regional findings rather than failing entirely.

**Cost estimate:** $7.20/month per unused IP (PREMIUM network tier default)

**Required permissions:**
- `compute.addresses.list` (included in `roles/compute.viewer`)
- `compute.globalAddresses.list` (included in `roles/compute.viewer`)

---

### Platform Waste

#### Idle Cloud SQL Instances

**Rule ID:** `gcp.sql.instance.idle`

**What it detects:** Cloud SQL instances in `RUNNABLE` state with zero database connections for 7+ days

**Confidence:**

- **HIGH:** Monitoring confirms zero connections for the full 7-day window

**Risk:** HIGH

**Why this matters:**
- Cloud SQL bills continuously for vCPU and memory regardless of query load
- A `db-n1-standard-2` costs ~$93/month with zero queries
- Dev and staging databases are frequently left running after feature branches merge or projects wind down
- Cloud SQL is the highest-cost idle resource type in most GCP environments

**Detection logic:**
```python
for instance in sql_admin_api.list(project_id):
    if instance.state == "RUNNABLE" and not is_read_replica(instance):
        if not has_connections(monitoring_client, project_id, instance.name, days=7):
            flag(instance)
```

**Conservative monitoring fallback:** If Cloud Monitoring is unavailable or permission-denied, the instance is assumed active — it is not flagged. This avoids false positives when monitoring data is temporarily unavailable.

**Read replicas excluded:** Read replicas have no independent billing basis — the primary instance cost is what matters.

**Cost estimates by tier:**

| Tier | ~Monthly cost |
|---|---|
| `db-f1-micro` | $7.67 |
| `db-g1-small` | $25.22 |
| `db-n1-standard-1` | $46.55 |
| `db-n1-standard-2` | $93.10 |
| `db-n1-standard-4` | $186.19 |
| `db-n1-highmem-2` | $113.45 |
| `db-n1-highmem-4` | $226.90 |

Costs are approximate for us-central1 with HA disabled.

**Required permissions:**
- `cloudsql.instances.list` (included in `roles/cloudsql.viewer`)
- `monitoring.timeSeries.list` (included in `roles/monitoring.viewer`)

---

### AI/ML Waste (opt-in — `--category ai`)

#### Idle Vertex AI Online Prediction Endpoints

**Rule ID:** `gcp.vertex.endpoint.idle`

**What it detects:** Vertex AI Online Prediction endpoints with `dedicatedResources.minReplicaCount > 0` and zero prediction requests for 14+ days

**Confidence:**

- **HIGH:** Zero predictions for the full 14-day window (endpoint age ≥ 14 days)
- **MEDIUM:** Zero predictions, endpoint age ≥ 75% of threshold (≥ 10.5 days), or age unknown

**Risk:** HIGH (GPU-backed endpoints: T4, V100, A100, L4, H100, TPU), MEDIUM (CPU-only)

**Why this matters:**
- Vertex AI endpoints with `minReplicaCount > 0` keep dedicated compute running 24/7 regardless of traffic
- GPU endpoints (T4: $311/month per GPU, A100: $2,933/month, H100: $8,000/month) are especially costly when idle
- Experiment and prototype endpoints are commonly abandoned after demos without being deleted or scaled to zero
- Endpoints using `automaticResources` (which scale to zero) are excluded — only `dedicatedResources` incur idle cost

**Detection logic:**
```python
for endpoint in vertex_ai_api.list(project_id, location="-"):  # all locations
    total_min_replicas = sum(
        m.dedicatedResources.minReplicaCount
        for m in endpoint.deployedModels
        if m.dedicatedResources  # skip automaticResources
    )
    if total_min_replicas > 0:
        if not has_predictions(monitoring_client, endpoint_id, days=14):
            flag(endpoint)
```

**Conservative monitoring fallback:** If Cloud Monitoring is unavailable or permission-denied, the endpoint is assumed active — it is not flagged.

**Cost estimates by machine type (per node, us-central1):**

| Machine Type | ~Monthly cost/node |
|---|---|
| `n1-standard-4` | $138 |
| `n1-standard-8` | $277 |
| `n1-standard-4` + T4 GPU | $449 |
| `n1-standard-4` + V100 GPU | $1,523 |
| `a2-highgpu-1g` (A100 40GB) | $2,933 |
| `a2-highgpu-2g` (2× A100) | $5,866 |
| `a2-ultragpu-1g` (A100 80GB) | $5,103 |
| `g2-standard-8` (L4 GPU) | $1,060 |

Costs are approximate for us-central1, on-demand. Multiply by `minReplicaCount` for total monthly idle cost.

**Required permissions:**
- `aiplatform.endpoints.list` (included in `roles/aiplatform.viewer`)
- `monitoring.timeSeries.list` (included in `roles/monitoring.viewer`)

---

## Rule Stability Guarantee

Once a rule reaches production status:
- Rule ID remains stable
- Confidence semantics unchanged
- Backwards compatibility preserved
- Schema additions only (no breaking changes)

This guarantees trust for long-running CI/CD integrations.

---

## Coming Soon

**AI/ML (all providers):**
- Vertex AI endpoints with zero predictions (GCP)
- Orphaned SageMaker training artifacts in S3 (AWS)

**AWS:**
- S3 lifecycle gaps, Redshift idle, NAT Gateway routing waste

**Azure:**
- Azure Firewall idle, AKS node pool idle, Azure Batch unused pools

**GCP:**
- GKE node pool idle, BigQuery slot waste, GCS cold storage, Cloud Run idle revisions

**Multi-Cloud:**
- Rule filtering (`--rules` flag)
- Policy-as-code (`cleancloud.yaml`)

---

**Next:** [AWS Setup →](aws.md) | [Azure Setup →](azure.md) | [GCP Setup →](gcp.md) | [CI/CD Integration →](ci.md)
