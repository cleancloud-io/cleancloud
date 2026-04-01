resource "aws_iam_role" "cleancloud" {
  name        = var.role_name
  description = "CleanCloud read-only role for cross-account scanning"

  assume_role_policy = var.external_id != "" ? jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.hub_account_id}:root"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.external_id
        }
      }
    }]
  }) : jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.hub_account_id}:root"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(var.tags, {
    ManagedBy = "CleanCloud"
    Purpose   = "CrossAccountReadOnlyScanning"
  })
}

resource "aws_iam_role_policy" "cleancloud_ai" {
  count = var.enable_ai ? 1 : 0

  name = "CleanCloudAIReadOnly"
  role = aws_iam_role.cleancloud.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SageMakerReadOnly"
        Effect = "Allow"
        Action = [
          "sagemaker:ListEndpoints",
          "sagemaker:DescribeEndpoint",
          "sagemaker:DescribeEndpointConfig",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "cleancloud" {
  name = "CleanCloudReadOnly"
  role = aws_iam_role.cleancloud.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2ReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots",
          "ec2:DescribeImages",
          "ec2:DescribeAddresses",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeNatGateways",
          "ec2:DescribeRegions",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
        ]
        Resource = "*"
      },
      {
        Sid    = "ELBReadOnly"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
        ]
        Resource = "*"
      },
      {
        Sid    = "RDSReadOnly"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBSnapshots",
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchReadOnly"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "cloudwatch:GetMetricStatistics",
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketTagging",
        ]
        Resource = "*"
      },
      {
        Sid      = "STSIdentity"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      },
    ]
  })
}
