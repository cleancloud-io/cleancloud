from datetime import datetime, timezone
from typing import List

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_NOW = datetime(2026, 2, 24, 14, 32, 0, tzinfo=timezone.utc)

AWS_FINDINGS: List[Finding] = [
    Finding(
        provider="aws",
        rule_id="aws.ec2.instance.stopped",
        resource_type="aws.ec2.instance",
        resource_id="i-0a3f2c1d4e5b67890",
        region="us-east-1",
        title="Stopped EC2 Instance (55 Days)",
        summary=(
            "EC2 instance 'i-0a3f2c1d4e5b67890' (t3.xlarge) has been stopped for "
            "55 days. Attached EBS volumes continue to accrue storage charges even "
            "while the instance is off."
        ),
        reason="Instance has been in 'stopped' state for 55+ days",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "instance_type": "t3.xlarge",
            "availability_zone": "us-east-1b",
            "stop_time": "2025-12-31T09:15:00+00:00",
            "days_stopped": 55,
            "attached_volume_ids": ["vol-0root123abc", "vol-0data456def"],
            "total_ebs_gb": 250,
            "days_stopped_threshold": 30,
            "tags": {"Name": "migration-source", "Project": "platform-rewrite"},
        },
        evidence=Evidence(
            signals_used=[
                "Instance has been in 'stopped' state for 55 days",
                "Stopped at: 2025-12-31 09:15 UTC",
                "Instance type: t3.xlarge",
                "2 attached EBS volumes (250 GB total) — accruing ~$25.0/month in storage charges",
            ],
            signals_not_checked=[
                "Planned reactivation or standby use",
                "Disaster recovery intent",
                "Pending migration or handoff",
            ],
            time_window="55 days",
        ),
        estimated_monthly_cost_usd=25.0,
    ),
    Finding(
        provider="aws",
        rule_id="aws.ebs.volume.unattached",
        resource_type="aws.ebs.volume",
        resource_id="vol-0a1b2c3d4e5f67890",
        region="us-east-1",
        title="Unattached EBS Volume",
        summary="EBS volume has been unattached for 47 days",
        reason="Volume has been unattached for 47 days",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "size_gb": 500,
            "availability_zone": "us-east-1a",
            "state": "available",
            "age_days": 47,
            "tags": {"Project": "legacy-api", "Owner": "platform"},
        },
        evidence=Evidence(
            signals_used=["volume state: available", "no attachment records"],
            signals_not_checked=[],
        ),
        estimated_monthly_cost_usd=40.0,
    ),
    Finding(
        provider="aws",
        rule_id="aws.ec2.nat_gateway.idle",
        resource_type="aws.ec2.nat_gateway",
        resource_id="nat-0abcdef1234567890",
        region="us-west-2",
        title="Idle NAT Gateway",
        summary="NAT Gateway with no traffic for 21 days",
        reason="No traffic detected for 21 days",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.MEDIUM,
        detected_at=_NOW,
        details={
            "name": "staging-nat",
            "state": "available",
            "vpc_id": "vpc-0abc123",
            "total_bytes_out": 0,
            "total_bytes_in": 0,
            "idle_threshold_days": 14,
        },
        evidence=Evidence(
            signals_used=[
                "CloudWatch BytesOutToDestination: 0",
                "CloudWatch BytesInFromDestination: 0",
            ],
            signals_not_checked=[],
            time_window="21 days",
        ),
        estimated_monthly_cost_usd=32.40,
    ),
    Finding(
        provider="aws",
        rule_id="aws.rds.instance.idle",
        resource_type="aws.rds.instance",
        resource_id="db-legacy-reporting",
        region="us-east-1",
        title="Idle RDS Instance",
        summary="RDS instance with near-zero connections for 30 days",
        reason="Average connections < 1 for 30 days",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "engine": "mysql",
            "instance_class": "db.t3.large",
            "multi_az": False,
            "avg_connections": 0.2,
            "idle_threshold_days": 30,
        },
        evidence=Evidence(
            signals_used=["CloudWatch DatabaseConnections avg < 1", "no recent snapshots"],
            signals_not_checked=[],
            time_window="30 days",
        ),
        estimated_monthly_cost_usd=97.0,
    ),
    Finding(
        provider="aws",
        rule_id="aws.ec2.elastic_ip.unattached",
        resource_type="aws.ec2.elastic_ip",
        resource_id="eipalloc-0a1b2c3d4e5f6",
        region="eu-west-1",
        title="Unattached Elastic IP",
        summary="Elastic IP not associated with any instance or ENI",
        reason="Elastic IP not associated with any instance or ENI (age: 92 days)",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "public_ip": "52.18.xxx.xxx",
            "domain": "vpc",
            "age_days": 92,
        },
        evidence=Evidence(
            signals_used=["no association found", "allocation age 92 days"],
            signals_not_checked=[],
        ),
        estimated_monthly_cost_usd=None,
    ),
    Finding(
        provider="aws",
        rule_id="aws.ec2.security_group.unused",
        resource_type="aws.ec2.security_group",
        resource_id="sg-0c9d8e7f6a5b4c3d2",
        region="us-east-1",
        title="Unused Security Group",
        summary=(
            "Security group 'app-server-sg' (sg-0c9d8e7f6a5b4c3d2) in VPC vpc-0abc123 "
            "is not associated with any network interface."
        ),
        reason="Security group has no ENI associations",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.MEDIUM,
        detected_at=_NOW,
        details={
            "sg_name": "app-server-sg",
            "vpc_id": "vpc-0abc123",
            "description": "App server inbound rules — legacy stack",
            "rule_count": 4,
            "tags": {"Project": "legacy-api", "Owner": "platform"},
        },
        evidence=Evidence(
            signals_used=[
                "No ENI associations found for this security group",
                "Security group name: 'app-server-sg' (sg-0c9d8e7f6a5b4c3d2)",
                "VPC: vpc-0abc123",
                "Group has 4 rule(s) defined but no attached interfaces",
            ],
            signals_not_checked=[
                "Groups referenced only in other groups' inbound rules (no ENI attachment)",
                "Service-managed groups (RDS, ELB, Lambda) between deployments",
                "Recently created groups awaiting resource association",
            ],
            time_window=None,
        ),
        estimated_monthly_cost_usd=None,
    ),
    Finding(
        provider="aws",
        rule_id="aws.rds.snapshot.old",
        resource_type="aws.rds.snapshot",
        resource_id="rds:prod-mysql-2025-10-04-03-27",
        region="us-east-1",
        title="Old Manual RDS Snapshot (112 Days)",
        summary=(
            "Manual RDS snapshot 'rds:prod-mysql-2025-10-04-03-27' of 'prod-mysql' "
            "is 112 days old and accruing storage charges."
        ),
        reason="Manual RDS snapshot exceeds 90-day retention threshold",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "db_instance_id": "prod-mysql",
            "engine": "mysql",
            "size_gb": 200,
            "age_days": 112,
            "age_threshold_days": 90,
            "create_time": "2025-10-04T03:27:00+00:00",
            "tags": {"Project": "platform", "Env": "prod"},
        },
        evidence=Evidence(
            signals_used=[
                "Manual RDS snapshot is 112 days old (threshold: 90 days)",
                "Created at: 2025-10-04",
                "Source DB instance: prod-mysql",
                "Engine: mysql",
                "Size: 200 GB",
                "Accruing ~$19.0/month in snapshot storage (~$0.095/GB-month)",
            ],
            signals_not_checked=[
                "Compliance or audit retention requirements",
                "Disaster recovery intent",
                "Referenced by application or runbook",
                "Cross-region restore dependency",
            ],
            time_window="112 days",
        ),
        estimated_monthly_cost_usd=19.0,
    ),
]

AZURE_FINDINGS: List[Finding] = [
    Finding(
        provider="azure",
        rule_id="azure.unattached_disk",
        resource_type="azure.compute.disk",
        resource_id="data-disk-legacy-api",
        region="eastus",
        title="Unattached Managed Disk",
        summary="Managed disk not attached to any VM",
        reason="Managed disk not attached to any VM (age: 34 days)",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.MEDIUM,
        detected_at=_NOW,
        details={
            "size_gb": 256,
            "disk_state": "Unattached",
            "subscription": "Production",
            "age_days": 34,
        },
        evidence=Evidence(
            signals_used=["disk state: Unattached", "no VM attachment"],
            signals_not_checked=[],
        ),
        estimated_monthly_cost_usd=20.48,
    ),
    Finding(
        provider="azure",
        rule_id="azure.public_ip_unused",
        resource_type="azure.network.public_ip",
        resource_id="pip-old-gateway",
        region="westeurope",
        title="Unused Public IP",
        summary="Public IP not associated with any resource",
        reason="Public IP not associated with any resource",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "ip_address": "20.82.xxx.xxx",
            "allocation_method": "Static",
            "subscription": "Staging",
        },
        evidence=Evidence(
            signals_used=["no ip_configuration association"],
            signals_not_checked=[],
        ),
        estimated_monthly_cost_usd=None,
    ),
    Finding(
        provider="azure",
        rule_id="azure.vm_stopped_not_deallocated",
        resource_type="azure.compute.vm",
        resource_id="vm-old-jumpbox",
        region="eastus",
        title="Stopped VM (Not Deallocated)",
        summary="VM is stopped but not deallocated — compute charges still apply",
        reason="VM in stopped state for 18 days — not deallocated, billing continues",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "vm_size": "Standard_D2s_v3",
            "power_state": "Stopped",
            "subscription": "Production",
            "stopped_days": 18,
        },
        evidence=Evidence(
            signals_used=["power state: Stopped (not Deallocated)"],
            signals_not_checked=[],
        ),
        estimated_monthly_cost_usd=70.08,
    ),
    Finding(
        provider="azure",
        rule_id="azure.app_service.idle",
        resource_type="azure.app_service",
        resource_id=(
            "/subscriptions/29d91ee0-922f-483a-a81f-1a5eff4ecfa2"
            "/resourceGroups/rg-staging/providers/Microsoft.Web/sites/api-staging"
        ),
        region="eastus",
        title="Idle App Service (21 Days)",
        summary=(
            "App Service 'api-staging' has received zero HTTP requests for 21 days "
            "but continues to accrue Standard tier charges."
        ),
        reason="Zero HTTP requests over 21-day window on a paid App Service plan",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "app_name": "api-staging",
            "sku_tier": "Standard",
            "state": "Running",
            "kind": "app",
            "idle_threshold_days": 14,
            "tags": {"Env": "staging", "Team": "backend"},
        },
        evidence=Evidence(
            signals_used=[
                "Azure Monitor Requests metric: 0 total over 21 days",
                "App Service plan tier: Standard (paid)",
                "App state: Running",
            ],
            signals_not_checked=[
                "Background jobs or webjobs with no HTTP traffic",
                "Internal VNet-only traffic not captured by Requests metric",
                "Planned reactivation or seasonal use",
            ],
            time_window="21 days",
        ),
        estimated_monthly_cost_usd=73.0,
    ),
    Finding(
        provider="azure",
        rule_id="azure.container_registry.unused",
        resource_type="azure.container_registry",
        resource_id=(
            "/subscriptions/29d91ee0-922f-483a-a81f-1a5eff4ecfa2"
            "/resourceGroups/rg-platform/providers"
            "/Microsoft.ContainerRegistry/registries/acrlegacybuild"
        ),
        region="westeurope",
        title="Unused Container Registry (95 Days)",
        summary=(
            "Container registry 'acrlegacybuild' has had zero image pulls for 95 days "
            "and is accruing Standard tier charges."
        ),
        reason="No image pulls detected for 95 days (threshold: 90 days)",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "registry_name": "acrlegacybuild",
            "sku": "Standard",
            "days_unused_threshold": 90,
            "tags": {"Project": "legacy-build", "Team": "platform"},
        },
        evidence=Evidence(
            signals_used=[
                "Azure Monitor SuccessfulPullCount: 0 over 95 days",
                "ACR SKU: Standard",
            ],
            signals_not_checked=[
                "Push activity (images may still be written but not pulled)",
                "Geo-replication or audit retention requirements",
            ],
            time_window="95 days",
        ),
        estimated_monthly_cost_usd=20.0,
    ),
]

GCP_FINDINGS: List[Finding] = [
    Finding(
        provider="gcp",
        rule_id="gcp.compute.disk.unattached",
        resource_type="gcp.compute.disk",
        resource_id="projects/my-project/zones/us-central1-a/disks/data-pipeline-scratch",
        region="us-central1-a",
        title="Unattached Persistent Disk",
        summary=(
            "Persistent disk 'data-pipeline-scratch' (500 GB, pd-ssd) in zone "
            "'us-central1-a' is not attached to any VM but continues to incur "
            "storage charges (~$85.0/month, estimated, region-dependent)."
        ),
        reason="Disk has no attached VM (users list is empty)",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "disk_name": "data-pipeline-scratch",
            "disk_type": "pd-ssd",
            "size_gb": 500,
            "location": "us-central1-a",
            "is_regional": False,
            "last_detach_timestamp": "2025-12-18T11:45:00+00:00",
            "labels": {"team": "data-eng", "env": "staging"},
        },
        evidence=Evidence(
            signals_used=[
                "Disk status: READY",
                "No VM users (users list empty)",
                "Disk type: pd-ssd (~$0.17/GB/month storage)",
                "Size: 500 GB → ~$85.0/month (estimated, region-dependent)",
                "Last detached: 1656h ago",
            ],
            signals_not_checked=[
                "Disk reserved for imminent VM recreation",
                "Snapshot-only workflow (intentional detachment)",
                "Cross-project disk sharing",
            ],
        ),
        estimated_monthly_cost_usd=85.0,
    ),
    Finding(
        provider="gcp",
        rule_id="gcp.compute.ip.unused",
        resource_type="gcp.compute.address",
        resource_id="projects/my-project/regions/us-central1/addresses/old-lb-frontend",
        region="us-central1",
        title="Unused Reserved External IP",
        summary=(
            "Regional static IP 'old-lb-frontend' (34.118.xxx.xxx) in 'us-central1' "
            "is reserved but not attached to any resource, billing ~$7.20/month (estimated)."
        ),
        reason="IP address status is RESERVED — not attached to any VM, LB, or NAT gateway",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "address_name": "old-lb-frontend",
            "ip_address": "34.118.xxx.xxx",
            "address_type": "EXTERNAL",
            "region": "us-central1",
            "scope": "regional",
            "is_regional": True,
            "network_tier": "PREMIUM",
            "labels": {"project": "decommissioned-api"},
        },
        evidence=Evidence(
            signals_used=[
                "Address status: RESERVED (not IN_USE)",
                "Address type: EXTERNAL",
                "Network tier: PREMIUM",
                "IP: 34.118.xxx.xxx",
                "~$7.20/month (PREMIUM tier reference, estimated)",
            ],
            signals_not_checked=[
                "IP held for imminent re-attachment",
                "Compliance or security requirement to hold specific IP",
            ],
        ),
        estimated_monthly_cost_usd=7.20,
    ),
    Finding(
        provider="gcp",
        rule_id="gcp.compute.vm.stopped",
        resource_type="gcp.compute.instance",
        resource_id="projects/my-project/zones/us-central1-b/instances/dev-sandbox-vm",
        region="us-central1",
        title="Stopped VM (68 Days)",
        summary=(
            "VM 'dev-sandbox-vm' (n2-standard-4) in zone 'us-central1-b' has been "
            "TERMINATED for 68 days. Attached disks (2 disk(s), 200 GB) continue "
            "billing at ~$8.0/month."
        ),
        reason="VM has been in TERMINATED state for 68 days",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.MEDIUM,
        detected_at=_NOW,
        details={
            "instance_name": "dev-sandbox-vm",
            "machine_type": "n2-standard-4",
            "zone": "us-central1-b",
            "total_disk_gb": 200,
            "boot_disk_count": 1,
            "days_stopped": 68,
            "days_stopped_threshold": 30,
            "stop_time": "2025-12-17T14:00:00+00:00",
            "automatic_restart": False,
            "labels": {"env": "dev", "owner": "ml-team"},
        },
        evidence=Evidence(
            signals_used=[
                "Instance status: TERMINATED",
                "Stopped for 68 days (since 2025-12-17T14:00:00+00:00)",
                "Attached disks: 2 persistent disk(s), 200 GB total",
                "Estimated disk cost: ~$8.0/month (pd-standard rate — see caveats)",
                "Boot disk present (1 boot disk(s)) — strong indicator of an abandoned environment",
            ],
            signals_not_checked=[
                "Planned seasonal or scheduled shutdown",
                "IaC-managed environment pending recreation",
                "Data preserved intentionally for forensics",
                "Disk types (pd-ssd, pd-balanced, hyperdisk) may have higher costs",
            ],
            time_window="30 days",
        ),
        estimated_monthly_cost_usd=8.0,
    ),
    Finding(
        provider="gcp",
        rule_id="gcp.compute.snapshot.old",
        resource_type="gcp.compute.snapshot",
        resource_id="projects/my-project/global/snapshots/pre-migration-backup-2025-09",
        region="global",
        title="Old Disk Snapshot (153 Days)",
        summary=(
            "Snapshot 'pre-migration-backup-2025-09' (400 GB) is 153 days old and "
            "its source disk no longer exists. Estimated storage cost: ~$10.4/month."
        ),
        reason="Snapshot is 153 days old (threshold: 90 days)",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "snapshot_name": "pre-migration-backup-2025-09",
            "disk_size_gb": 400,
            "storage_bytes": 0,
            "days_old": 153,
            "days_old_threshold": 90,
            "created_at": "2025-09-23T08:00:00+00:00",
            "source_disk_deleted": True,
            "storage_locations": ["us"],
            "labels": {"purpose": "pre-migration", "team": "platform"},
        },
        evidence=Evidence(
            signals_used=[
                "Snapshot age: 153 days (created 2025-09-23)",
                "Status: READY",
                "Disk size: 400 GB",
                "Estimated cost: ~$10.4/month (disk size used as proxy)",
                "Source disk reference missing — likely orphaned snapshot "
                "(GCP clears sourceDisk when the backing disk is deleted)",
            ],
            signals_not_checked=[
                "Compliance or regulatory data retention requirements",
                "Disaster recovery snapshot policy",
                "Part of an active backup rotation",
                "Snapshot storage is incremental — actual reclaim may differ",
            ],
            time_window="90 days",
        ),
        estimated_monthly_cost_usd=10.4,
    ),
    Finding(
        provider="gcp",
        rule_id="gcp.sql.instance.idle",
        resource_type="gcp.sql.instance",
        resource_id="projects/my-project/instances/staging-postgres",
        region="us-central1",
        title="Idle Cloud SQL Instance (7+ Days)",
        summary=(
            "Cloud SQL instance 'staging-postgres' (POSTGRES_14, db-n1-standard-2) "
            "in region 'us-central1' has had no observed database connections via "
            "Cloud Monitoring over 14+ days but continues to incur compute charges."
        ),
        reason="Zero database connections detected over the last 14 days",
        risk=RiskLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "instance_name": "staging-postgres",
            "database_version": "POSTGRES_14",
            "tier": "db-n1-standard-2",
            "region": "us-central1",
            "ha_enabled": False,
            "days_idle_threshold": 14,
            "estimated_monthly_cost_usd": 93.10,
            "data_disk_size_gb": "100",
            "data_disk_type": "PD_SSD",
            "labels": {"env": "staging", "app": "backend-api"},
        },
        evidence=Evidence(
            signals_used=[
                "Instance state: RUNNABLE",
                "Zero TCP connections observed via Cloud Monitoring over 14 days "
                "(metric: cloudsql.googleapis.com/database/network/connections)",
                "Database version: POSTGRES_14",
                "Tier 'db-n1-standard-2' costs ~$93.10/month (compute only, no HA)",
                "Storage: 100 GB (PD_SSD) — billed separately from compute",
            ],
            signals_not_checked=[
                "Short-lived or batch connections (cron jobs, ETL)",
                "Non-TCP workloads or Unix socket connections via Cloud SQL Proxy",
                "Planned reactivation for upcoming sprint",
                "Storage, backups, HA, and network egress not included in cost estimate",
            ],
            time_window="14 days",
        ),
        estimated_monthly_cost_usd=93.10,
    ),
]

GCP_AI_FINDINGS: List[Finding] = [
    Finding(
        provider="gcp",
        rule_id="gcp.vertex.endpoint.idle",
        resource_type="gcp.vertex.endpoint",
        resource_id="projects/my-project/locations/us-central1/endpoints/8842019374650589184",
        region="us-central1",
        title="Idle Vertex AI Endpoint (No Predictions for 21 Days)",
        summary=(
            "Vertex AI endpoint 'llm-serving-v2' in 'us-central1' has received zero predictions "
            "for 21 days but keeps 1 dedicated node running continuously, incurring compute charges."
        ),
        reason=(
            "Vertex AI endpoint has zero predictions for 21 days "
            "with dedicated capacity (minReplicaCount=1)"
        ),
        risk=RiskLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "endpoint_id": "8842019374650589184",
            "display_name": "llm-serving-v2",
            "location": "us-central1",
            "machine_type": "n1-standard-4",
            "accelerator_type": "NVIDIA_TESLA_T4",
            "accelerator_count": 1,
            "is_gpu": True,
            "min_replica_count": 1,
            "age_days": 21,
            "idle_window_days": 21,
            "idle_days_threshold": 14,
            "estimated_monthly_cost": "~$449/month",
        },
        evidence=Evidence(
            signals_used=[
                "Zero prediction requests for 21 days "
                "(Cloud Monitoring: aiplatform.googleapis.com/prediction/online/request_count)",
                "Dedicated capacity configured: minReplicaCount=1 "
                "(always-on compute — billed continuously regardless of traffic)",
                "Endpoint age: 21 days",
                "Machine type: n1-standard-4",
                "Accelerator: NVIDIA_TESLA_T4 × 1",
                "GPU-backed endpoint — high continuous cost",
                "Display name: llm-serving-v2",
            ],
            signals_not_checked=[
                "Scheduled or batch prediction requests outside the observation window",
                "Internal health-check or canary traffic not tracked by Cloud Monitoring",
                "Planned future usage or upcoming model promotion",
                "Shadow mode or A/B test routing with low traffic share",
                "Endpoints kept warm for latency-sensitive production traffic",
            ],
            time_window="21 days",
        ),
        estimated_monthly_cost_usd=449.0,
    ),
]

ALL_FINDINGS: List[Finding] = AWS_FINDINGS + AZURE_FINDINGS + GCP_FINDINGS

AZURE_AI_FINDINGS: List[Finding] = [
    Finding(
        provider="azure",
        rule_id="azure.aml.compute.idle",
        resource_type="azure.aml.compute",
        resource_id=(
            "/subscriptions/29d91ee0-922f-483a-a81f-1a5eff4ecfa2"
            "/resourceGroups/rg-ml-platform"
            "/providers/Microsoft.MachineLearningServices"
            "/workspaces/ml-platform-prod"
            "/computes/gpu-train-cluster"
        ),
        region="East US",
        title="Idle Azure ML Compute Cluster (Baseline Capacity Waste for 21 Days)",
        summary=(
            "AML compute cluster 'gpu-train-cluster' in workspace 'ml-platform-prod' "
            "is configured to keep 2 node(s) always running (min_node_count=2) but no "
            "workload activity was observed for 21 days — baseline capacity waste."
        ),
        reason="AML compute cluster has min_node_count=2 with no workload activity for 21 days",
        risk=RiskLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "cluster_name": "gpu-train-cluster",
            "workspace_name": "ml-platform-prod",
            "resource_group": "rg-ml-platform",
            "vm_size": "Standard_NC6s_v3",
            "min_node_count": 2,
            "is_gpu": True,
            "age_days": 21,
            "idle_window_days": 21,
            "idle_days_threshold": 14,
            "estimated_monthly_cost": "~$4,406/month",
            "cost_estimate_type": "mapped",
        },
        evidence=Evidence(
            signals_used=[
                "Cluster configured with non-zero baseline capacity but no workload observed for 21 days (Azure Monitor: Active Nodes)",
                "Baseline cost driver: min_node_count=2 (always-on compute — billed continuously)",
                "Compute type: AmlCompute",
                "Cluster age: 21 days",
                "VM size: Standard_NC6s_v3",
                "GPU cluster with no workload — high-cost idle state",
            ],
            signals_not_checked=[
                "Scheduled or periodic training jobs",
                "Jobs submitted outside the observation window",
                "Planned future usage",
                "Cluster configured with min_node_count for warm-start latency",
                "Cluster reserved for interactive development",
            ],
            time_window="21 days",
        ),
        estimated_monthly_cost_usd=4406.0,
    ),
]

AWS_AI_FINDINGS: List[Finding] = [
    Finding(
        provider="aws",
        rule_id="aws.sagemaker.endpoint.idle",
        resource_type="aws.sagemaker.endpoint",
        resource_id="llm-inference-prod",
        region="us-east-1",
        title="Idle SageMaker Endpoint (No Invocations for 21 Days)",
        summary=(
            "SageMaker endpoint 'llm-inference-prod' has received zero invocations "
            "for 21 days but remains InService, incurring continuous GPU charges."
        ),
        reason="SageMaker endpoint has zero invocations for 21 days",
        risk=RiskLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        detected_at=_NOW,
        details={
            "endpoint_name": "llm-inference-prod",
            "instance_type": "ml.g5.2xlarge",
            "is_gpu": True,
            "variant_count": 1,
            "total_instances": 1,
            "age_days": 21,
            "idle_window_days": 21,
            "idle_days_threshold": 14,
            "estimated_monthly_cost": "~$1,008/month",
        },
        evidence=Evidence(
            signals_used=[
                "Zero recorded invocations for 21 days (CloudWatch metric)",
                "Endpoint state: InService",
                "Endpoint age: 21 days",
                "Total running instances (DesiredInstanceCount): 1",
                "Instance type: ml.g5.2xlarge",
                "GPU-backed instance — high hourly cost",
            ],
            signals_not_checked=[
                "Scheduled or batch invocation patterns",
                "Internal health-check invocations",
                "Planned future usage",
                "Shadow mode / canary deployments",
            ],
            time_window="21 days",
        ),
        estimated_monthly_cost_usd=1008.0,
    ),
]
