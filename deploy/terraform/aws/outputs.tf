output "role_arn" {
  description = "ARN of the CleanCloud IAM role."
  value       = aws_iam_role.cleancloud.arn
}

output "role_name" {
  description = "Name of the CleanCloud IAM role."
  value       = aws_iam_role.cleancloud.name
}
