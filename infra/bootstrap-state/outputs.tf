output "bucket_name" {
  description = "Name of the S3 bucket that stores Terraform state."
  value       = aws_s3_bucket.terraform_state.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket that stores Terraform state."
  value       = aws_s3_bucket.terraform_state.arn
}

output "aws_account_id" {
  description = "AWS account in which the state bucket is managed."
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS region containing the state bucket."
  value       = var.aws_region
}
