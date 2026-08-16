locals {
  common_tags = {
    Project     = "icpr-dissertation"
    Environment = "measurement"
    ManagedBy   = "terraform"
  }
}

resource "aws_vpc" "measurement" {
  cidr_block                       = "10.20.0.0/16"
  enable_dns_support               = true
  enable_dns_hostnames             = true
  assign_generated_ipv6_cidr_block = false

  tags = merge(local.common_tags, {
    Name = "icpr-measurement-vpc"
  })
}

resource "aws_subnet" "measurement_public" {
  vpc_id                          = aws_vpc.measurement.id
  cidr_block                      = "10.20.1.0/24"
  availability_zone               = var.availability_zone
  map_public_ip_on_launch         = true
  assign_ipv6_address_on_creation = false

  tags = merge(local.common_tags, {
    Name = "icpr-measurement-public"
  })
}

resource "aws_internet_gateway" "measurement" {
  vpc_id = aws_vpc.measurement.id

  tags = merge(local.common_tags, {
    Name = "icpr-measurement-igw"
  })
}

resource "aws_route_table" "measurement_public" {
  vpc_id = aws_vpc.measurement.id

  tags = merge(local.common_tags, {
    Name = "icpr-measurement-public"
  })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.measurement_public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.measurement.id
}

resource "aws_route_table_association" "measurement_public" {
  subnet_id      = aws_subnet.measurement_public.id
  route_table_id = aws_route_table.measurement_public.id
}
