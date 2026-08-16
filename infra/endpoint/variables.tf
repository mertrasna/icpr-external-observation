variable "resource_name_prefix" {
  description = "Short lowercase prefix used to make globally unique resource names."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,30}[a-z0-9]$", var.resource_name_prefix))
    error_message = "resource_name_prefix must be 4-32 lowercase letters, digits, or hyphens."
  }
}

variable "availability_zone" {
  description = "Availability zone for the public measurement subnet."
  type        = string
  default     = "eu-central-1a"

  validation {
    condition     = can(regex("^eu-central-1[a-z]$", var.availability_zone))
    error_message = "The availability zone must be in eu-central-1."
  }
}

variable "admin_cidr" {
  description = "Single public IPv4 /32 permitted to connect to SSH."
  type        = string

  validation {
    condition = (
      can(cidrhost(var.admin_cidr, 0)) &&
      can(regex("^[0-9]{1,3}(\\.[0-9]{1,3}){3}/32$", var.admin_cidr)) &&
      var.admin_cidr != "0.0.0.0/0"
    )
    error_message = "admin_cidr must be one valid IPv4 address with a /32 prefix; 0.0.0.0/0 is forbidden."
  }
}

variable "ssh_public_key_path" {
  description = "Path to the existing SSH public key used for the EC2 key pair."
  type        = string

  validation {
    condition     = endswith(var.ssh_public_key_path, ".pub")
    error_message = "ssh_public_key_path must reference a .pub public-key file."
  }
}

variable "ami_id" {
  description = "Pinned official Canonical Ubuntu Server 24.04 LTS x86_64 AMI ID."
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.ami_id))
    error_message = "ami_id must be a valid EC2 AMI ID."
  }
}

variable "instance_type" {
  description = "T3 instance type for the measurement endpoint."
  type        = string
  default     = "t3.small"

  validation {
    condition     = can(regex("^t3\\.(nano|micro|small|medium|large|xlarge|2xlarge)$", var.instance_type))
    error_message = "instance_type must be a standard T3 instance type."
  }
}

variable "root_volume_size" {
  description = "Encrypted gp3 root-volume size in GiB."
  type        = number
  default     = 40

  validation {
    condition = (
      var.root_volume_size >= 8 &&
      var.root_volume_size <= 16384 &&
      floor(var.root_volume_size) == var.root_volume_size
    )
    error_message = "root_volume_size must be a whole number between 8 and 16384 GiB."
  }
}
