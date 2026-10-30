# CloudFormation fixtures

`aws-cloudformation-templates/`: templates from aws-cloudformation/aws-cloudformation-templates
at a0f43bc6d20813052892546f445037cf84c75b54 (Apache License 2.0, `LICENSE.txt`): every template
where Frame or checkov reports one of the compared checks, YAML only where a JSON twin exists,
plus two JSON twins.

`checkov.json`: what checkov 3.4.0 reports on each of them for its checks equivalent to Frame's
AWS policies (security groups open to the internet, public RDS, unencrypted RDS/EBS, public S3
ACLs, full-admin IAM). `tests/test_iac_cloudformation.py` requires every one of them to be a
Frame finding or a Frame `undecided`, and lists what Frame reports beyond them.
