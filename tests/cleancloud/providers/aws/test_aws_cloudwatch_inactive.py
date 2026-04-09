from cleancloud.providers.aws.rules.cloudwatch_inactive import (
    find_inactive_cloudwatch_logs,
)


def test_find_inactive_cloudwatch_logs(mock_boto3_session):
    region = "us-east-1"

    logs = mock_boto3_session._logs

    # Mock paginator correctly
    paginator = logs.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "logGroups": [
                {
                    "logGroupName": "/aws/lambda/never-expire",
                    # retentionInDays missing -> infinite retention
                    "storedBytes": 12345,
                },
                {
                    "logGroupName": "/aws/lambda/expire-30",
                    "retentionInDays": 30,
                },
            ]
        }
    ]

    findings = find_inactive_cloudwatch_logs(mock_boto3_session, region)
    resource_ids = {f.resource_id for f in findings}

    # Positive
    assert "/aws/lambda/never-expire" in resource_ids

    # Negative
    assert "/aws/lambda/expire-30" not in resource_ids
