data "aws_ami" "ubuntu" {
  owners = ["099720109477"]

  filter {
    name   = "image-id"
    values = [var.ami_id]
  }

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_instance" "measurement" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.measurement_public.id
  vpc_security_group_ids      = [aws_security_group.measurement_endpoint.id]
  key_name                    = aws_key_pair.measurement.key_name
  iam_instance_profile        = aws_iam_instance_profile.measurement.name
  associate_public_ip_address = false
  enable_primary_ipv6         = false
  source_dest_check           = true
  monitoring                  = false

  user_data                   = file("${path.module}/cloud-init.yaml")
  user_data_replace_on_change = false

  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  credit_specification {
    cpu_credits = "standard"
  }

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  lifecycle {
    # The provider reads the directly associated EIP as a public address and
    # otherwise proposes instance replacement despite no launch-time public IP.
    ignore_changes = [associate_public_ip_address]
  }

  volume_tags = merge(local.common_tags, {
    Name = "icpr-measurement-endpoint-root"
  })

  tags = merge(local.common_tags, {
    Name = "icpr-measurement-endpoint"
  })
}

resource "aws_eip" "measurement" {
  domain = "vpc"

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "icpr-measurement-endpoint"
  })
}

resource "aws_eip_association" "measurement" {
  allocation_id        = aws_eip.measurement.id
  network_interface_id = aws_instance.measurement.primary_network_interface_id
  allow_reassociation  = false
}
