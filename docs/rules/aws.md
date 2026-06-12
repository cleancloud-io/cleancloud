# AWS Rules

20 rules (13 hygiene + 7 AI/ML). AI/ML rules require `--category ai`.

← [Back to index](../rules.md)

| Rule ID | Cost Surface | What It Detects |
|---|---|---|
| `aws.ec2.instance.stopped` | Compute | EC2 instances stopped 30+ days (EBS charges continue) |
| `aws.ec2.security_group.unused` | Governance | Security groups with no ENI associations |
| `aws.ebs.unattached` | Storage | EBS volumes not attached to any instance |
| `aws.ebs.snapshot.old` | Storage | Snapshots ≥ 90 days old |
| `aws.ec2.ami.old` | Storage | AMIs older than 180 days |
| `aws.ec2.elastic_ip.unattached` | Network | Elastic IPs not associated with any instance or network interface |
| `aws.ec2.eni.detached` | Network | Detached ENIs not currently attached |
| `aws.ec2.nat_gateway.idle` | Network | NAT Gateways with zero traffic 14+ days |
| `aws.elbv2.alb.idle` / `aws.elbv2.nlb.idle` / `aws.elb.clb.idle` | Network | Load balancers with zero traffic 14+ days |
| `aws.rds.instance.idle` | Platform | RDS instances with zero connections 14+ days |
| `aws.rds.snapshot.old` | Storage | Manual RDS snapshots older than 90 days |
| `aws.cloudwatch.logs.infinite_retention` | Observability | Log groups with no retention policy |
| `aws.resource.untagged` | Governance | EC2/S3/CloudWatch resources with zero tags |
| `aws.sagemaker.endpoint.idle` | AI/ML | Real-time SageMaker endpoints with no traffic 14+ days |
| `aws.sagemaker.notebook.idle` | AI/ML | SageMaker Notebook Instances with stale activity 14+ days |
| `aws.ec2.gpu.idle` | AI/ML | EC2 GPU/accelerator instances with <5% GPU or <10% CPU over 7 days |
| `aws.bedrock.provisioned_throughput.idle` | AI/ML | Bedrock Provisioned Throughput with zero invocations 7+ days |
| `aws.sagemaker.domain.idle` | AI/ML | SageMaker Domains with no running apps 30+ days (continuous EFS cost) |
| `aws.sagemaker.studio_app.idle` | AI/ML | SageMaker Studio apps with no usable activity 7+ days |
| `aws.sagemaker.training_job.long_running` | AI/ML | SageMaker training jobs still running beyond threshold |

---

## Compute

#### `aws.ec2.instance.stopped`
**Detects:** EC2 instances in `stopped` state for 30+ days; EBS volumes continue accruing charges

**Confidence / Risk:** HIGH (CloudTrail stop event ≥ 30 days, restart-cycle aware) / MEDIUM

**Permissions:** `ec2:DescribeInstances`, `ec2:DescribeVolumes`, `cloudtrail:LookupEvents`

**Params:** none

**Exclusions:** none

**Spec:** [specs/aws/ec2_stopped.md](../specs/aws/ec2_stopped.md)

---

## Governance

#### `aws.ec2.security_group.unused`
**Detects:** Security groups with no ENI associations

**Confidence / Risk:** MEDIUM (no ENI associations found) / LOW

**Permissions:** `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`

**Params:** none

**Exclusions:** `default` security group (AWS prevents deletion)

**Spec:** [specs/aws/ec2_sg_unused.md](../specs/aws/ec2_sg_unused.md)

#### `aws.resource.untagged`
**Detects:** EC2 volumes, S3 buckets, and CloudWatch Log Groups with zero tags

**Confidence / Risk:** HIGH (deterministic from authoritative tag source) / MEDIUM

**Permissions:** `ec2:DescribeVolumes`, `s3:ListAllMyBuckets`, `s3:GetBucketTagging`, `logs:DescribeLogGroups`, `logs:ListTagsForResource`

**Params:** none

**Exclusions:** none

**Spec:** [specs/aws/untagged_resources.md](../specs/aws/untagged_resources.md)

---

## Storage

#### `aws.ebs.unattached`
**Detects:** EBS volumes in `available` state for 7+ days

**Confidence / Risk:** MEDIUM (`available` state ≥ 7 days) / LOW

**Permissions:** `ec2:DescribeVolumes`

**Params:** none

**Exclusions:** volumes younger than 7 days

**Spec:** [specs/aws/ebs_unattached.md](../specs/aws/ebs_unattached.md)

#### `aws.ebs.snapshot.old`
**Detects:** EBS snapshots older than `days_old`

**Confidence / Risk:** LOW (age alone is a weak signal) / LOW

**Permissions:** `ec2:DescribeSnapshots`, `ec2:DescribeSnapshotAttribute`

**Params:** `days_old` (default: 90)

**Exclusions:** snapshots linked to registered AMIs

**Spec:** [specs/aws/ebs_snapshot_old.md](../specs/aws/ebs_snapshot_old.md)

#### `aws.ec2.ami.old`
**Detects:** AMIs older than `days_old` in `available` state

**Confidence / Risk:** MEDIUM (age + state) / HIGH–LOW (varies by usage signal)

**Permissions:** `ec2:DescribeImages`

**Params:** `days_old` (default: 180)

**Exclusions:** AMIs not in `available` state

**Spec:** [specs/aws/ami_old.md](../specs/aws/ami_old.md)

#### `aws.rds.snapshot.old`
**Detects:** Manual RDS snapshots older than `days_old`

**Confidence / Risk:** LOW (age alone is a weak signal) / LOW

**Permissions:** `rds:DescribeDBSnapshots`, `rds:DescribeDBSnapshotAttributes`

**Params:** `days_old` (default: 90)

**Exclusions:** automated snapshots (`SnapshotType=automated`), snapshots not in `available` state

**Spec:** [specs/aws/rds_snapshot_old.md](../specs/aws/rds_snapshot_old.md)

---

## Network

#### `aws.ec2.elastic_ip.unattached`
**Detects:** Elastic IPs with all four association fields absent

**Confidence / Risk:** HIGH (deterministic state, no age threshold) / LOW

**Permissions:** `ec2:DescribeAddresses`

**Params:** none

**Exclusions:** Classic EIPs without `AllocationTime` are annotated but not excluded

**Spec:** [specs/aws/elastic_ip_unattached.md](../specs/aws/elastic_ip_unattached.md)

#### `aws.ec2.eni.detached`
**Detects:** ENIs in `available` (detached) state

**Confidence / Risk:** HIGH (`Status=available`, no temporal threshold) / LOW

**Permissions:** `ec2:DescribeNetworkInterfaces`

**Params:** none

**Exclusions:** none (Lambda/ECS/RDS managed ENIs included and annotated)

**Spec:** [specs/aws/eni_detached.md](../specs/aws/eni_detached.md)

#### `aws.ec2.nat_gateway.idle`
**Detects:** NAT Gateways with zero traffic across all 5 CloudWatch metrics for `idle_threshold_days`

**Confidence / Risk:** HIGH (zero traffic + no route table refs); MEDIUM (zero traffic, route refs exist) / MEDIUM

**Permissions:** `ec2:DescribeNatGateways`, `cloudwatch:GetMetricStatistics`

**Params:** `idle_threshold_days` (default: 14)

**Exclusions:** gateways younger than threshold; any metric with no datapoints → skip

**Spec:** [specs/aws/nat_gateway_idle.md](../specs/aws/nat_gateway_idle.md)

#### `aws.elbv2.alb.idle` / `aws.elbv2.nlb.idle` / `aws.elb.clb.idle`
**Detects:** Load balancers with zero traffic for `idle_threshold_days`

**Confidence / Risk:** HIGH (zero traffic + no registered targets); MEDIUM (zero traffic only) / MEDIUM

**Permissions:** `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeTargetGroups`, `elasticloadbalancing:DescribeTargetHealth`, `cloudwatch:GetMetricStatistics`

**Params:** `idle_threshold_days` (default: 14)

**Exclusions:** LBs younger than threshold

**Spec:** [specs/aws/elb_idle.md](../specs/aws/elb_idle.md)

---

## Platform

#### `aws.rds.instance.idle`
**Detects:** RDS instances with zero `DatabaseConnections` for `idle_threshold_days`

**Confidence / Risk:** MEDIUM (zero connections; proxies may obscure usage) / MEDIUM

**Permissions:** `rds:DescribeDBInstances`, `cloudwatch:GetMetricStatistics`

**Params:** `idle_threshold_days` (default: 14)

**Exclusions:** Aurora cluster members, read replicas, instances younger than threshold

**Spec:** [specs/aws/rds_idle.md](../specs/aws/rds_idle.md)

---

## Observability

#### `aws.cloudwatch.logs.infinite_retention`
**Detects:** CloudWatch Log Groups with no retention policy set

**Confidence / Risk:** HIGH (directly observable config fact) / HIGH (≥ 1 GB stored), MEDIUM (> 0 bytes), LOW (empty)

**Permissions:** `logs:DescribeLogGroups`

**Params:** none

**Exclusions:** none

**Spec:** [specs/aws/cloudwatch_logs_no_retention.md](../specs/aws/cloudwatch_logs_no_retention.md)

---

## AI/ML *(opt-in: `--category ai`)*

#### `aws.sagemaker.endpoint.idle`
**Detects:** Real-time SageMaker endpoints `InService` with zero invocations across all billable production variants for `idle_days`

**Confidence / Risk:** HIGH (all variants confirmed zero traffic); MEDIUM (at least one variant missing datapoints) / HIGH (accelerator-backed variants: ml.g*, ml.p*, ml.inf*, ml.trn*); MEDIUM (CPU-only)

**Permissions:** `sagemaker:ListEndpoints`, `sagemaker:DescribeEndpoint`, `sagemaker:DescribeEndpointConfig`, `cloudwatch:GetMetricStatistics`

**Params:** `idle_days` (default: 14)

**Exclusions:** async inference endpoints (`AsyncInferenceConfig` set), serverless variants without current provisioned concurrency

**Spec:** [specs/aws/ai/sagemaker_endpoint_idle.md](../specs/aws/ai/sagemaker_endpoint_idle.md)

#### `aws.sagemaker.notebook.idle`
**Detects:** SageMaker Notebook Instances `InService` with stale `LastModifiedTime` for `idle_days` (control-plane heuristic, not direct Jupyter activity)

**Confidence / Risk:** MEDIUM (weak heuristic) / HIGH (GPU/accelerator instances: ml.g4dn, ml.g5, ml.p3, ml.p4d, ml.p4de, ml.p5, Inferentia, Trainium); MEDIUM (CPU)

**Permissions:** `sagemaker:ListNotebookInstances`

**Params:** `idle_days` (default: 14)

**Exclusions:** `Stopped` instances (out of scope)

**Spec:** [specs/aws/ai/sagemaker_notebook_idle.md](../specs/aws/ai/sagemaker_notebook_idle.md)

#### `aws.ec2.gpu.idle`
**Detects:** EC2 GPU/accelerator instances (p/g/trn/inf/dl families) with max GPU utilization < 5% or max daily CPU < 10% over `idle_days`

**Confidence / Risk:** HIGH (`nvidia_smi_utilization_gpu` discoverable in CloudWatch and max GPU < threshold); MEDIUM (metric not discoverable — CPU proxy only, max daily CPU < threshold) / CRITICAL (`idle_ratio >= 2.0`); HIGH (otherwise)

**Permissions:** `ec2:DescribeInstances`, `cloudwatch:GetMetricStatistics`, `cloudwatch:ListMetrics`

**Params:** `idle_days` (default: 7), `gpu_threshold` (default: 5.0%), `cpu_threshold` (default: 10.0%)

**Exclusions:** non-GPU instance families; missing, naive, or future `LaunchTime`; instances younger than threshold; no CloudWatch datapoints on chosen metric path

**Spec:** [specs/aws/ai/ec2_gpu_idle.md](../specs/aws/ai/ec2_gpu_idle.md)

#### `aws.bedrock.provisioned_throughput.idle`
**Detects:** Bedrock Provisioned Throughput (Model Units) with zero invocations for `idle_days`; bills per MU per hour regardless of traffic

**Confidence / Risk:** HIGH (zero invocations confirmed + age ≥ `idle_days`) / HIGH

**Permissions:** `bedrock:ListProvisionedModelThroughputs`, `cloudwatch:GetMetricStatistics`

**Params:** `idle_days` (default: 7)

**Exclusions:** none

**Spec:** [specs/aws/ai/bedrock_provisioned_idle.md](../specs/aws/ai/bedrock_provisioned_idle.md)

#### `aws.sagemaker.domain.idle`
**Detects:** SageMaker Domains `InService` with no apps in `InService` or `Pending` state across all user profiles and spaces for `idle_days_threshold` of domain age (continuous EFS storage cost)

**Confidence / Risk:** HIGH (fully paginated ListApps control-plane state) / HIGH (`HomeEfsFileSystemId` present); MEDIUM (no EFS)

**Permissions:** `sagemaker:ListDomains`, `sagemaker:DescribeDomain`, `sagemaker:ListApps`

**Params:** `idle_days_threshold` (default: 30)

**Exclusions:** non-`InService` domains; domains younger than threshold; any app in `InService` or `Pending` state; unclassifiable app status entries

**Spec:** [specs/aws/ai/sagemaker_domain_idle.md](../specs/aws/ai/sagemaker_domain_idle.md)

#### `aws.sagemaker.studio_app.idle`
**Detects:** SageMaker Studio `KernelGateway`/`JupyterLab`/`CodeEditor` apps `InService` with no usable recent activity for `idle_days_threshold`

**Confidence / Risk:** HIGH (usable activity signal present and ≥ threshold); skipped if `LastUserActivityTimestamp == LastHealthCheckTimestamp` / HIGH (GPU/accelerator: ml.g4dn, ml.g5, ml.p2–p5, ml.trn1, ml.inf1/2); MEDIUM (CPU)

**Permissions:** `sagemaker:ListApps`, `sagemaker:DescribeApp`

**Params:** `idle_days_threshold` (default: 7)

**Exclusions:** `JupyterServer` app type; apps where `LastUserActivityTimestamp == LastHealthCheckTimestamp` (health check artifact)

**Spec:** [specs/aws/ai/sagemaker_studio_app_idle.md](../specs/aws/ai/sagemaker_studio_app_idle.md)

#### `aws.sagemaker.training_job.long_running`
**Detects:** SageMaker training jobs still `InProgress` beyond `long_running_hours_threshold`

**Confidence / Risk:** HIGH (elapsed time exceeds configured stopping-condition limit); MEDIUM (threshold exceeded, no stopping-condition limit) / CRITICAL (HIGH confidence + GPU/accelerator); HIGH (HIGH confidence + non-GPU); MEDIUM (all MEDIUM confidence)

**Permissions:** `sagemaker:ListTrainingJobs`, `sagemaker:DescribeTrainingJob`

**Params:** `long_running_hours_threshold` (default: 24)

**Exclusions:** completed/stopped jobs; spot jobs use `MaxWaitTimeInSeconds`, not `MaxRuntimeInSeconds`

**Spec:** [specs/aws/ai/sagemaker_training_job_long_running.md](../specs/aws/ai/sagemaker_training_job_long_running.md)

#### `aws.sagemaker.processing_job.long_running`
**Detects:** SageMaker processing jobs still `InProgress` beyond `long_running_hours_threshold`

**Confidence / Risk:** HIGH (elapsed time exceeds `MaxRuntimeInSeconds` after processing has started); MEDIUM (threshold exceeded without an exceeded applicable runtime limit) / HIGH (accelerator-backed: `ml.g*`, `ml.p*`, `ml.inf*`, `ml.trn*`); MEDIUM (other)

**Permissions:** `sagemaker:ListProcessingJobs`, `sagemaker:DescribeProcessingJob`

**Params:** `long_running_hours_threshold` (default: 24)

**Exclusions:** completed/stopped jobs; malformed required timestamps; `ProcessingStartTime` future beyond skew; `ProcessingStartTime < CreationTime` beyond skew tolerance

**Spec:** [specs/aws/ai/sagemaker_processing_job_long_running.md](../specs/aws/ai/sagemaker_processing_job_long_running.md)
