provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.project_tags
  }
}

data "aws_caller_identity" "current" {}
