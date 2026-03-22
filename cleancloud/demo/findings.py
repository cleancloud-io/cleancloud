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
]

ALL_FINDINGS: List[Finding] = AWS_FINDINGS + AZURE_FINDINGS
