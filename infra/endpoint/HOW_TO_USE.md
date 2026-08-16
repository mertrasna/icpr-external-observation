# How to use the endpoint stack

## Purpose

This stack creates the AWS network, EC2 measurement endpoint, restricted SSH
rule, Elastic IP, IAM role, and encrypted evidence bucket used by the study.

## Configure

```sh
cd infra/endpoint
cp backend.hcl.example backend.hcl
cp terraform.tfvars.example terraform.tfvars
```

Replace every placeholder. `admin_cidr` must be one IPv4 `/32`; use a reviewed
Ubuntu 24.04 AMI and an existing SSH public key. Use the same reviewed
`resource_name_prefix` convention as the state stack.

## Review

```sh
terraform init -reconfigure -backend-config=backend.hcl
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform show tfplan
```

Only after reviewing cost, security rules, retention resources, and the saved
plan should an authorised operator run `terraform apply tfplan`. Useful outputs
include `elastic_public_ipv4`, `primary_private_ipv4`, `security_group_id`, and
`measurement_data_bucket_name`. Continue with `server/HOW_TO_USE.md`.
