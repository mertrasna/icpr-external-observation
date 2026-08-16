output "vpc_id" {
  description = "ID of the dedicated measurement VPC."
  value       = aws_vpc.measurement.id
}

output "vpc_cidr" {
  description = "IPv4 CIDR block of the dedicated measurement VPC."
  value       = aws_vpc.measurement.cidr_block
}

output "public_subnet_id" {
  description = "ID of the public measurement subnet."
  value       = aws_subnet.measurement_public.id
}

output "public_subnet_cidr" {
  description = "IPv4 CIDR block of the public measurement subnet."
  value       = aws_subnet.measurement_public.cidr_block
}

output "availability_zone" {
  description = "Availability zone of the public measurement subnet."
  value       = aws_subnet.measurement_public.availability_zone
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway attached to the measurement VPC."
  value       = aws_internet_gateway.measurement.id
}

output "public_route_table_id" {
  description = "ID of the route table associated with the public measurement subnet."
  value       = aws_route_table.measurement_public.id
}

output "security_group_id" {
  description = "ID of the endpoint security group."
  value       = aws_security_group.measurement_endpoint.id
}

output "ec2_key_pair_name" {
  description = "Name of the EC2 key pair for the measurement endpoint."
  value       = aws_key_pair.measurement.key_name
}

output "ec2_key_fingerprint" {
  description = "Fingerprint reported by AWS for the imported EC2 public key."
  value       = aws_key_pair.measurement.fingerprint
}

output "ssh_admin_cidr" {
  description = "Administrator IPv4 /32 permitted to connect over SSH."
  value       = var.admin_cidr
}

output "instance_id" {
  description = "ID of the measurement endpoint EC2 instance."
  value       = aws_instance.measurement.id
}

output "pinned_ami_id" {
  description = "Pinned Canonical Ubuntu AMI used by the endpoint."
  value       = data.aws_ami.ubuntu.id
}

output "pinned_ami_name" {
  description = "Name of the pinned Canonical Ubuntu AMI."
  value       = data.aws_ami.ubuntu.name
}

output "instance_type" {
  description = "EC2 instance type of the measurement endpoint."
  value       = aws_instance.measurement.instance_type
}

output "primary_private_ipv4" {
  description = "Primary private IPv4 address of the measurement endpoint."
  value       = aws_instance.measurement.private_ip
}

output "primary_network_interface_id" {
  description = "ID of the EC2 instance's primary network interface."
  value       = aws_instance.measurement.primary_network_interface_id
}

output "eip_allocation_id" {
  description = "Allocation ID of the persistent Elastic IP."
  value       = aws_eip.measurement.allocation_id
}

output "eip_association_id" {
  description = "ID of the direct Elastic IP association."
  value       = aws_eip_association.measurement.id
}

output "elastic_public_ipv4" {
  description = "Persistent public IPv4 address of the measurement endpoint."
  value       = aws_eip.measurement.public_ip
}

output "root_volume_size" {
  description = "Encrypted gp3 root-volume size in GiB."
  value       = var.root_volume_size
}

output "suggested_ssh_command" {
  description = "Suggested SSH command for the measurement endpoint."
  value       = "ssh -i /path/to/private-key ubuntu@${aws_eip.measurement.public_ip}"
}

output "measurement_data_bucket_name" {
  description = "Name of the encrypted, versioned S3 measurement-evidence bucket."
  value       = aws_s3_bucket.measurement_data.id
}

output "measurement_data_prefix" {
  description = "S3 key prefix writable by the measurement endpoint."
  value       = local.measurement_data_prefix
}

output "measurement_upload_role_arn" {
  description = "ARN of the EC2 role restricted to measurement-evidence uploads."
  value       = aws_iam_role.measurement_upload.arn
}

output "measurement_instance_profile_name" {
  description = "Name of the instance profile attached to the measurement endpoint."
  value       = aws_iam_instance_profile.measurement.name
}
