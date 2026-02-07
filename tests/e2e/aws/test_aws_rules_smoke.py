from datetime import datetime

import boto3
import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.aws.rules.ami_old import find_old_amis
from cleancloud.providers.aws.rules.cloudwatch_inactive import find_inactive_cloudwatch_logs
from cleancloud.providers.aws.rules.ebs_snapshot_old import find_old_ebs_snapshots
from cleancloud.providers.aws.rules.ebs_unattached import find_unattached_ebs_volumes
from cleancloud.providers.aws.rules.elastic_ip_unattached import find_unattached_elastic_ips
from cleancloud.providers.aws.rules.eni_detached import find_detached_enis
from cleancloud.providers.aws.rules.nat_gateway_idle import find_idle_nat_gateways
from cleancloud.providers.aws.rules.untagged_resources import find_untagged_resources


@pytest.mark.e2e
@pytest.mark.aws
def test_aws_rules_run_without_error():
    session = boto3.Session()
    region = "us-east-1"  # default test region

    all_rules = [
        find_unattached_ebs_volumes(session, region),
        find_old_ebs_snapshots(session, region),
        find_inactive_cloudwatch_logs(session, region),
        find_unattached_elastic_ips(session, region),
        find_detached_enis(session, region),
        find_untagged_resources(session, region),
        find_old_amis(session, region),
        find_idle_nat_gateways(session, region),
    ]

    for rule_results in all_rules:
        assert isinstance(rule_results, list), f"Rule returned {type(rule_results)} instead of list"
        for f in rule_results:
            assert isinstance(f, Finding)
            assert f.provider == "aws"
            assert f.rule_id.startswith("aws.")
            assert f.resource_id
            assert f.region
            assert f.detected_at and isinstance(f.detected_at, datetime)
