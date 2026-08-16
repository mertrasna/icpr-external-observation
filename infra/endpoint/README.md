# Measurement endpoint infrastructure

This Terraform stack creates the AWS network, EC2 endpoint, restricted SSH
rule, Elastic IP, upload-only instance role, and encrypted evidence bucket used
by the measurement server.

Start with [HOW_TO_USE.md](HOW_TO_USE.md). Copy the backend and variable
examples, replace every placeholder, and run the formatting/validation/plan
steps from this directory. `terraform apply` creates billable resources and
requires an explicit review.

## Security properties

- SSH accepts one administrator IPv4 `/32`; `0.0.0.0/0` is rejected.
- The evidence bucket blocks public access, enforces HTTPS, enables versioning,
  and has destruction protection.
- The instance role can upload only beneath its assigned prefix. It cannot list
  or delete the bucket, and no AWS access key is stored on the instance.
- The root volume is encrypted and the Ubuntu AMI is an explicit input.

The checked-in examples contain documentation addresses and placeholders only.
Never commit `backend.hcl`, `terraform.tfvars`, state, saved plans, or cloud
credentials.
