# How to use the infrastructure

## Purpose

This folder contains Terraform for the optional AWS remote-state bucket and the
controlled measurement endpoint. Applying it creates billable cloud resources.

## Deployment order

1. `bootstrap-state/`: create the encrypted, versioned Terraform state bucket.
2. `endpoint/`: create the VPC, EC2 endpoint, security group, Elastic IP, IAM
   role, and evidence bucket.
3. `server/`: install and verify the measurement software on that endpoint.

## Quick offline check

```sh
terraform fmt -check -recursive infra
```

This only checks formatting. `init`, `validate`, and `plan` may download
providers or contact AWS; `apply` creates resources.

Copy and edit only the example files in each stack. Never commit generated
state, a real backend file, `terraform.tfvars`, or a saved plan. Continue with
the `HOW_TO_USE.md` in each stack.
