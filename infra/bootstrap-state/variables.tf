variable "aws_region" {
  description = "AWS region in which the remote-state bucket is created."
  type        = string
  default     = "eu-central-1"

  validation {
    condition     = var.aws_region == "eu-central-1"
    error_message = "The iCPR state bucket must be created in eu-central-1."
  }
}

variable "resource_name_prefix" {
  description = "Short lowercase prefix used to make the state-bucket name globally unique."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,30}[a-z0-9]$", var.resource_name_prefix))
    error_message = "resource_name_prefix must be 4-32 lowercase letters, digits, or hyphens."
  }
}

variable "project_tags" {
  description = "Tags applied to every supported bootstrap resource."
  type        = map(string)
  default = {
    Environment = "bootstrap"
    ManagedBy   = "Terraform"
    Project     = "iCPR"
    Purpose     = "TerraformRemoteState"
  }
}
