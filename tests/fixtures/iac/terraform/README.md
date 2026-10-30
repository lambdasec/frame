# Terraform fixtures

- `terragoat/`: the `.tf` files of bridgecrewio/terragoat at
  729f8da62c6a85ce4af5ad3d123de97776d954c4 (Apache License 2.0, `LICENSE`), a deliberately
  vulnerable configuration. The sample AWS credentials it contains (`terraform/aws/ec2.tf` lines
  15-16, `lambda.tf` lines 45-46, `providers.tf` lines 10-11) are replaced with a placeholder:
  this repository never holds a credential-shaped string.
- `terraform-aws-rds/`: the `.tf` files of terraform-aws-modules/terraform-aws-rds at
  175da043429cbbe41c512f976105719f6d0e538c (Apache License 2.0, `LICENSE`): a module, its
  submodules and examples that call it through local sources.

`*.expected.jsonl.gz`: every attribute's value as HashiCorp's HCL library evaluates it
(tests/iac_real/hcl).
