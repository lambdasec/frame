# Ground truth for the HCL evaluator

HashiCorp's own HCL library (`github.com/hashicorp/hcl/v2/hclsyntax`, pinned in `go.mod`) and
go-cty's functions, with Terraform's own `coalesce`, `length`, `lookup` and `to*` conversions
(`internal/lang/funcs`, reimplemented here with the same semantics), evaluating every attribute
of every module under a directory. The context is what a module sees before anything is
created: variables from their `default`, `terraform.tfvars` and `*.auto.tfvars`, converted to
their `type` (with `optional()` defaults); locals evaluated to a fixpoint; resources, data
sources, modules and `count`/`each` unknown; any other function unknown.

`tests/test_iac_terraform.py` evaluates the same attributes with `frame/iac/hcl.py` and requires,
for every one, HCL's value or an unknown: never a different value.

```bash
cd tests/iac_real/hcl && GOTOOLCHAIN=auto go build -o /tmp/hcldump .
F=../../fixtures/iac/terraform
for r in terragoat terraform-aws-rds; do /tmp/hcldump $F/$r | gzip -9 > $F/$r.expected.jsonl.gz; done
```

During development the same comparison ran on five terraform-aws-modules repositories (s3-bucket,
vpc, security-group, rds, eks) and TerraGoat: 16,243 attributes, none different, 57 unknown where
HCL knows the value.
