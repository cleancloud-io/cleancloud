from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from cleancloud.providers.aws.rules.elb_idle import find_idle_load_balancers


def _make_session(elbv2, elb, cloudwatch):
    """Create a mock session that returns the given clients."""
    session = MagicMock()

    def client_side_effect(service_name, *args, **kwargs):
        if service_name == "elbv2":
            return elbv2
        if service_name == "elb":
            return elb
        if service_name == "cloudwatch":
            return cloudwatch
        raise ValueError(f"Unexpected service: {service_name}")

    session.client.side_effect = client_side_effect
    return session


def _make_elbv2_lb(
    name="test-alb",
    lb_type="application",
    age_days=30,
    state="active",
):
    now = datetime.now(timezone.utc)
    arn = f"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/{name}/abc123"
    if lb_type == "network":
        arn = f"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/{name}/abc123"
    return {
        "LoadBalancerArn": arn,
        "LoadBalancerName": name,
        "Type": lb_type,
        "CreatedTime": now - timedelta(days=age_days),
        "State": {"Code": state},
        "DNSName": f"{name}.us-east-1.elb.amazonaws.com",
        "VpcId": "vpc-12345",
    }


def _make_clb(name="test-clb", age_days=30, instances=None):
    now = datetime.now(timezone.utc)
    return {
        "LoadBalancerName": name,
        "CreatedTime": now - timedelta(days=age_days),
        "DNSName": f"{name}.us-east-1.elb.amazonaws.com",
        "VPCId": "vpc-12345",
        "Instances": instances or [],
    }


def test_idle_alb_detected():
    """Idle ALB with zero requests and no targets should be flagged as HIGH confidence."""
    elbv2 = MagicMock()
    elb = MagicMock()
    cloudwatch = MagicMock()

    # ALB setup
    paginator = elbv2.get_paginator.return_value
    paginator.paginate.return_value = [
        {"LoadBalancers": [_make_elbv2_lb(name="idle-alb", age_days=30)]}
    ]

    elbv2.describe_target_groups.return_value = {"TargetGroups": []}
    cloudwatch.get_metric_statistics.return_value = {"Datapoints": []}

    # CLB setup - empty
    elb_paginator = elb.get_paginator.return_value
    elb_paginator.paginate.return_value = [{"LoadBalancerDescriptions": []}]

    session = _make_session(elbv2, elb, cloudwatch)
    findings = find_idle_load_balancers(session, "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "aws.elbv2.alb.idle"
    assert f.resource_type == "aws.elbv2.load_balancer"
    assert f.confidence.value == "high"
    assert f.risk.value == "medium"
    assert f.details["type"] == "application"
    assert f.details["has_targets"] is False
    assert "idle-alb" in f.resource_id


def test_active_alb_skipped():
    """ALB with traffic should NOT be flagged."""
    elbv2 = MagicMock()
    elb = MagicMock()
    cloudwatch = MagicMock()

    paginator = elbv2.get_paginator.return_value
    paginator.paginate.return_value = [
        {"LoadBalancers": [_make_elbv2_lb(name="active-alb", age_days=30)]}
    ]

    # Has traffic
    cloudwatch.get_metric_statistics.return_value = {"Datapoints": [{"Sum": 1000}]}

    elb_paginator = elb.get_paginator.return_value
    elb_paginator.paginate.return_value = [{"LoadBalancerDescriptions": []}]

    session = _make_session(elbv2, elb, cloudwatch)
    findings = find_idle_load_balancers(session, "us-east-1")

    assert len(findings) == 0


def test_idle_nlb_detected_unhealthy_targets():
    """Idle NLB with zero flows and only unhealthy targets should be HIGH confidence."""
    elbv2 = MagicMock()
    elb = MagicMock()
    cloudwatch = MagicMock()

    nlb = _make_elbv2_lb(name="idle-nlb", lb_type="network", age_days=20)
    paginator = elbv2.get_paginator.return_value
    paginator.paginate.return_value = [{"LoadBalancers": [nlb]}]

    elbv2.describe_target_groups.return_value = {"TargetGroups": [{"TargetGroupArn": "arn:tg"}]}
    elbv2.describe_target_health.return_value = {
        "TargetHealthDescriptions": [
            {"Target": {"Id": "i-123"}, "TargetHealth": {"State": "unhealthy"}}
        ]
    }
    cloudwatch.get_metric_statistics.return_value = {"Datapoints": []}

    elb_paginator = elb.get_paginator.return_value
    elb_paginator.paginate.return_value = [{"LoadBalancerDescriptions": []}]

    session = _make_session(elbv2, elb, cloudwatch)
    findings = find_idle_load_balancers(session, "us-east-1")

    nlb_findings = [f for f in findings if f.rule_id == "aws.elbv2.nlb.idle"]
    assert len(nlb_findings) == 1
    # Only unhealthy targets + no traffic -> HIGH confidence
    assert nlb_findings[0].confidence.value == "high"
    assert nlb_findings[0].details["has_targets"] is False


def test_idle_nlb_healthy_targets_medium_confidence():
    """Idle NLB with zero flows but healthy targets should be MEDIUM confidence."""
    elbv2 = MagicMock()
    elb = MagicMock()
    cloudwatch = MagicMock()

    nlb = _make_elbv2_lb(name="idle-nlb", lb_type="network", age_days=20)
    paginator = elbv2.get_paginator.return_value
    paginator.paginate.return_value = [{"LoadBalancers": [nlb]}]

    elbv2.describe_target_groups.return_value = {"TargetGroups": [{"TargetGroupArn": "arn:tg"}]}
    elbv2.describe_target_health.return_value = {
        "TargetHealthDescriptions": [
            {"Target": {"Id": "i-123"}, "TargetHealth": {"State": "healthy"}}
        ]
    }
    cloudwatch.get_metric_statistics.return_value = {"Datapoints": []}

    elb_paginator = elb.get_paginator.return_value
    elb_paginator.paginate.return_value = [{"LoadBalancerDescriptions": []}]

    session = _make_session(elbv2, elb, cloudwatch)
    findings = find_idle_load_balancers(session, "us-east-1")

    nlb_findings = [f for f in findings if f.rule_id == "aws.elbv2.nlb.idle"]
    assert len(nlb_findings) == 1
    # Healthy targets but no traffic -> MEDIUM confidence
    assert nlb_findings[0].confidence.value == "medium"
    assert nlb_findings[0].details["has_targets"] is True


def test_idle_clb_detected():
    """Idle CLB with zero requests and no instances should be flagged."""
    elbv2 = MagicMock()
    elb = MagicMock()
    cloudwatch = MagicMock()

    # elbv2 - empty
    elbv2_paginator = elbv2.get_paginator.return_value
    elbv2_paginator.paginate.return_value = [{"LoadBalancers": []}]

    # CLB setup
    clb = _make_clb(name="idle-clb", age_days=30, instances=[])
    elb_paginator = elb.get_paginator.return_value
    elb_paginator.paginate.return_value = [{"LoadBalancerDescriptions": [clb]}]

    cloudwatch.get_metric_statistics.return_value = {"Datapoints": []}

    session = _make_session(elbv2, elb, cloudwatch)
    findings = find_idle_load_balancers(session, "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "aws.elb.clb.idle"
    assert f.resource_type == "aws.elb.load_balancer"
    assert f.resource_id == "idle-clb"
    assert f.confidence.value == "high"  # No instances + no traffic
    assert f.details["has_instances"] is False


def test_young_lb_skipped():
    """LB younger than threshold should NOT be flagged."""
    elbv2 = MagicMock()
    elb = MagicMock()
    cloudwatch = MagicMock()

    # Young ALB (5 days old)
    paginator = elbv2.get_paginator.return_value
    paginator.paginate.return_value = [
        {"LoadBalancers": [_make_elbv2_lb(name="young-alb", age_days=5)]}
    ]

    # Young CLB (3 days old)
    elb_paginator = elb.get_paginator.return_value
    elb_paginator.paginate.return_value = [
        {"LoadBalancerDescriptions": [_make_clb(name="young-clb", age_days=3)]}
    ]

    session = _make_session(elbv2, elb, cloudwatch)
    findings = find_idle_load_balancers(session, "us-east-1")

    assert len(findings) == 0


def test_clb_with_instances_medium_confidence():
    """CLB with instances but no traffic should be MEDIUM confidence."""
    elbv2 = MagicMock()
    elb = MagicMock()
    cloudwatch = MagicMock()

    elbv2_paginator = elbv2.get_paginator.return_value
    elbv2_paginator.paginate.return_value = [{"LoadBalancers": []}]

    clb = _make_clb(
        name="idle-with-instances",
        age_days=30,
        instances=[{"InstanceId": "i-123"}],
    )
    elb_paginator = elb.get_paginator.return_value
    elb_paginator.paginate.return_value = [{"LoadBalancerDescriptions": [clb]}]

    cloudwatch.get_metric_statistics.return_value = {"Datapoints": []}

    session = _make_session(elbv2, elb, cloudwatch)
    findings = find_idle_load_balancers(session, "us-east-1")

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"
    assert findings[0].details["has_instances"] is True
    assert findings[0].details["instance_count"] == 1
