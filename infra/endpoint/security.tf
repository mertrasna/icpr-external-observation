resource "aws_security_group" "measurement_endpoint" {
  name        = "icpr-measurement-endpoint"
  description = "Network access for the iCPR measurement endpoint"
  vpc_id      = aws_vpc.measurement.id

  tags = merge(local.common_tags, {
    Name = "icpr-measurement-endpoint"
  })
}

resource "aws_vpc_security_group_ingress_rule" "ssh_admin" {
  security_group_id = aws_security_group.measurement_endpoint.id
  description       = "SSH administration from the configured administrator IPv4 address"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = var.admin_cidr

  tags = merge(local.common_tags, {
    Name = "icpr-ssh-admin"
  })
}

resource "aws_vpc_security_group_ingress_rule" "http" {
  security_group_id = aws_security_group.measurement_endpoint.id
  description       = "Public HTTP ingress"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"

  tags = merge(local.common_tags, {
    Name = "icpr-http"
  })
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.measurement_endpoint.id
  description       = "Public HTTPS ingress"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"

  tags = merge(local.common_tags, {
    Name = "icpr-https"
  })
}

resource "aws_vpc_security_group_ingress_rule" "http3" {
  security_group_id = aws_security_group.measurement_endpoint.id
  description       = "Public HTTP/3 ingress"
  ip_protocol       = "udp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"

  tags = merge(local.common_tags, {
    Name = "icpr-http3"
  })
}

resource "aws_vpc_security_group_egress_rule" "all_ipv4" {
  security_group_id = aws_security_group.measurement_endpoint.id
  description       = "Allow all outbound IPv4 traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = merge(local.common_tags, {
    Name = "icpr-all-ipv4-egress"
  })
}
