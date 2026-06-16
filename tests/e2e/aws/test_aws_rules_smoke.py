from datetime import datetime

import boto3
import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.aws.rules.ami_old import find_old_amis
from cleancloud.providers.aws.rules.cloudwatch_logs_no_retention import (
    find_cloudwatch_logs_no_retention,
)
from cleancloud.providers.aws.rules.ebs_snapshot_old import find_old_ebs_snapshots
from cleancloud.providers.aws.rules.ebs_unattached import find_unattached_ebs_volumes
from cleancloud.providers.aws.rules.ec2_sg_unused import find_unused_security_groups
from cleancloud.providers.aws.rules.ec2_stopped import find_stopped_ec2_instances
from cleancloud.providers.aws.rules.elastic_ip_unattached import (
    find_unattached_elastic_ips,
)
from cleancloud.providers.aws.rules.elb_idle import find_idle_load_balancers
from cleancloud.providers.aws.rules.eni_detached import find_detached_enis
from cleancloud.providers.aws.rules.nat_gateway_idle import find_idle_nat_gateways
from cleancloud.providers.aws.rules.rds_idle import find_idle_rds_instances
from cleancloud.providers.aws.rules.rds_snapshot_old import find_old_rds_snapshots
from cleancloud.providers.aws.rules.redshift_idle import find_idle_redshift_clusters
from cleancloud.providers.aws.rules.untagged_resources import find_untagged_resources


@pytest.mark.e2e
@pytest.mark.aws
def test_aws_rules_run_without_error():
    session = boto3.Session()
    region = "us-east-1"  # default test region

    rules = [
        find_unattached_ebs_volumes,
        find_old_ebs_snapshots,
        find_cloudwatch_logs_no_retention,
        find_unattached_elastic_ips,
        find_detached_enis,
        find_untagged_resources,
        find_old_amis,
        find_idle_nat_gateways,
        find_idle_rds_instances,
        find_idle_load_balancers,
        find_stopped_ec2_instances,
        find_unused_security_groups,
        find_old_rds_snapshots,
        find_idle_redshift_clusters,
    ]

    all_results = []
    for rule in rules:
        try:
            rule_results = rule(session, region)
        except PermissionError as e:
            pytest.fail(f"Missing IAM permissions for {rule.__name__}: {e}")
        except Exception as e:
            pytest.fail(f"Rule {rule.__name__} raised an unexpected error: {type(e).__name__}: {e}")
        assert isinstance(
            rule_results, list
        ), f"{rule.__name__} returned {type(rule_results)} instead of list"
        all_results.extend(rule_results)

    for f in all_results:
        assert isinstance(f, Finding)
        assert f.provider == "aws"
        assert f.rule_id.startswith("aws.")
        assert f.resource_id
        assert f.region
        assert f.detected_at and isinstance(f.detected_at, datetime)
