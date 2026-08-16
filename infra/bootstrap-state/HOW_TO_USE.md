# How to use the state bootstrap

## Purpose

This optional stack creates the private S3 bucket used for Terraform remote
state. It should normally be run once per AWS account.

## Configure and review

```sh
cd infra/bootstrap-state
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform show tfplan
```

Replace `resource_name_prefix` with a short value unique to your project before
initialising. It is part of the globally unique state-bucket name.

After explicit approval, run `terraform apply tfplan`. Use the resulting bucket
name to prepare the endpoint stack's private `backend.hcl`. State files, real
variables, credentials, and saved plans must not be committed.
