# Infrastructure as code

`frame iac` reads the infrastructure files in a repository into one model of resources and decides each policy on each resource with Z3. This release reads Kubernetes manifests (checked against the Pod Security Standards), Dockerfiles, Terraform and CloudFormation (AWS). Helm rendering and full network reachability follow ([roadmap](roadmap.md)).

```console
$ frame iac .
k8s/log-agent.yaml:13: [high] k8s-host-namespaces (CWE-668) DaemonSet/ops/log-agent: Pod shares the host's network, PID or IPC namespace [spec.template.spec.hostNetwork]
k8s/log-agent.yaml:24: [high] k8s-host-volume-types (CWE-668) DaemonSet/ops/log-agent: Pod mounts a volume type outside the restricted set [spec.template.spec.volumes[0].hostPath] (also k8s-host-path-volumes)
...
Infrastructure: 4 resource(s) in kubernetes: 4 file(s); 15 finding(s), 2 suppressed
```

`frame scan DIR --iac` adds the same results to a source scan (an `infrastructure` section in JSON, results in SARIF). A walkthrough: [examples/iac](../examples/iac/README.md).

## What is checked

**Kubernetes.** Every object with `apiVersion` and `kind` in a `.yaml`, `.yml` or `.json` file, the items of a `v1` `List` included. A Pod, and the pod template of a Deployment, ReplicaSet, DaemonSet, StatefulSet, Job, CronJob, ReplicationController or PodTemplate (in their own API groups, so another group's `Deployment` is not one), is checked against the 19 checks of the [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/), Baseline and Restricted, as the Pod Security admission controller of Kubernetes 1.38 runs them:

| Policy | Check | Level | Severity |
|---|---|---|---|
| `k8s-host-namespaces` | hostNetwork, hostPID, hostIPC | Baseline | high |
| `k8s-privileged` | a privileged container | Baseline | high |
| `k8s-capabilities-baseline` | a capability outside the runtime's default set | Baseline | high |
| `k8s-host-path-volumes` | a hostPath volume | Baseline | high |
| `k8s-windows-host-process` | a Windows HostProcess container | Baseline | high |
| `k8s-host-ports` | a host port | Baseline | medium |
| `k8s-apparmor` | an AppArmor profile overridden or disabled | Baseline | medium |
| `k8s-selinux` | an SELinux type, user or role outside the container values | Baseline | medium |
| `k8s-proc-mount` | an unmasked /proc | Baseline | medium |
| `k8s-seccomp-baseline` | seccomp explicitly Unconfined | Baseline | medium |
| `k8s-sysctls` | a sysctl outside the safe set | Baseline | medium |
| `k8s-host-probes` | a probe or lifecycle hook aimed at another host | Baseline | medium |
| `k8s-allow-privilege-escalation` | privilege escalation not disabled | Restricted | medium |
| `k8s-run-as-non-root` | may run as root | Restricted | medium |
| `k8s-run-as-user-root` | runs as UID 0 | Restricted | medium |
| `k8s-proc-mount-restricted` | an unmasked /proc, also in a user namespace | Restricted | medium |
| `k8s-host-volume-types` | a volume type outside the restricted set | Restricted | low |
| `k8s-seccomp-restricted` | seccomp not RuntimeDefault or Localhost | Restricted | low |
| `k8s-capabilities-restricted` | ALL not dropped, or a capability other than NET_BIND_SERVICE added | Restricted | low |

A Restricted check that replaces a Baseline one (as the admission controller replaces it at the Restricted level) is reported once where both hold, with the higher severity and `also` naming the replaced check: a container adding `SYS_ADMIN` is one `k8s-capabilities-restricted` finding at high, not two.

How close this is to Kubernetes itself, measured with the controller's own evaluator (`k8s.io/pod-security-admission/policy`, recorded by `tests/iac_real/psa`):

- On upstream's 148 test fixtures for 1.38, the checks that deny each pod at each level are the evaluator's, check for check, in 295 of 296 evaluations. The one difference is a volume with no source: the API server defaults it to `emptyDir`, and upstream lists that fixture as admitted, so Frame follows the cluster.
- On 450 workloads from four public repositories (GoogleCloudPlatform/microservices-demo, madhuakula/kubernetes-goat, kubernetes/examples, argoproj/argo-cd), the same in 881 of 900 evaluations. The rest are objects the evaluator's decoder rejects and Frame reads (removed `extensions/v1beta1` kinds, a string where the API wants a number), and the same `emptyDir` default.

**Dockerfiles.** `Dockerfile`, `Containerfile`, `*.Dockerfile` and `Dockerfile.*`, read as BuildKit reads them: Frame's parser is a port of BuildKit's (parser directives and the backtick escape, continuations with comments and blank lines inside, heredocs, JSON and shell forms, builder flags, `ENV a b`, ONBUILD), and on 345 files (BuildKit's own parser tests, real Dockerfiles from Docker's official images and samples, and 300 generated to stress it) it produces BuildKit's instructions, arguments, flags, lines and heredocs exactly, and fails where BuildKit fails. During development 16,000 generated files agreed as well. Each build stage is checked on its own:

| Policy | Check | Severity |
|---|---|---|
| `docker-credential-in-image` | a provider credential ([secret formats](../frame/sil/specs/data/secret-formats.toml)) in an ENV, ARG or LABEL value | high |
| `docker-root-user` | the image runs as root: its last USER is `root` or `0`, or it is `scratch` with none | medium |
| `docker-add-unverified-download` | ADD from an `http(s)` URL without `--checksum` | medium |
| `docker-user-not-set` | the image never sets a user, so it runs as its base image's | low |
| `docker-floating-base-image` | a base image with no tag or `latest`, and no digest | low |

The user an image runs as is resolved as Docker resolves it: the last USER of the final stage, else that of the stage it builds on (`FROM build`), root for `scratch`. A base image's own user is not in the files, so an image that never sets one makes `docker-root-user` undecided, and `docker-user-not-set` (which the file does entail) is reported instead. A value BuildKit expands from a build argument (`FROM ${BASE}`, `USER ${UID}`, `ADD ${URL}`) is unknown: `--build-arg` can change it, so policies on it are undecided rather than judged on the default. Compared with hadolint's base-image and root rules on the same files, every difference is a case Frame reads correctly: hadolint stops on three of BuildKit's test files with an untagged `FROM`, and reports three `FROM name-${ARG}` lines that name earlier build stages as untagged images.

**Terraform.** Every directory with `.tf` files is read as a root module, as a plan would see it before anything exists:

- Expressions are evaluated as HashiCorp's HCL library evaluates them (`frame/iac/hcl.py`: templates and heredocs, operators, conditionals, `for` expressions, splats, the common functions with Terraform's semantics). The contract is that an expression gets HCL's value or is unknown, never a different value. Checked against HCL itself (`tests/iac_real/hcl`): 16,243 attributes in TerraGoat and five terraform-aws-modules repositories, none different, 57 unknown where HCL has a value (mostly a conditional whose other branch is unknown, where HCL's type unification could change the chosen value).
- A variable takes the value of its module call, else `terraform.tfvars` / `*.auto.tfvars` (later files win), else its `default`, converted to its `type` (with `optional()` defaults). A variable with no value in the files (given at apply time) is unknown. Findings are for the values the repository gives; a `-var` on the command line is not in the files.
- What exists only once applied (`aws_vpc.main.id`) is one unknown per resource and attribute, the same wherever it is read; an attribute a resource configures is its value (`aws_s3_bucket.logs.bucket`).
- Known `count` and `for_each` expand to their instances (`count = 0` or an empty `for_each` leaves none); unknown ones leave one instance with `count.index` / `each` unknown. `dynamic` blocks expand over a known `for_each`. Local modules (`source = "./x"`), and modules `terraform init` recorded in `.terraform/modules/modules.json`, are read with their call's arguments.
- Not read yet: `.tf.json` files and override files (each is named in a warning).

| Policy | Check | Severity |
|---|---|---|
| `aws-sg-admin-from-internet` | a security group rule lets the internet reach SSH (22) or RDP (3389) | high |
| `aws-sg-all-from-internet` | a rule lets the internet reach every port | high |
| `aws-s3-public` | a bucket the public can read or write, through an ACL or bucket policy that takes effect | high |
| `aws-iam-full-admin` | an IAM policy (managed, inline, or a role's `inline_policy`) allowing every action on every resource | high |
| `aws-rds-public` | a database instance with a public endpoint | high |
| `aws-ebs-unencrypted` | an EBS volume this configuration leaves unencrypted | low |
| `aws-rds-unencrypted` | database storage this configuration leaves unencrypted | low |

Security group rules are read in all three forms (`ingress` blocks, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`), with protocol `-1` meaning every protocol and port. "The internet" is decided over the address space with Z3 (`frame/iac/addresses.py`): a CIDR lets the internet in when some address in it is globally reachable by IANA's special-purpose registries (the most specific block decides; multicast is never a source; IPv6 only within 2000::/3). So `0.0.0.0/1` counts and `100.64.0.0/10` does not; an IPv6 network in an IPv4 field is not a rule. A volume from a snapshot, or a database restored or replicated, takes its source's encryption, and `aws_ebs_encryption_by_default` in the same configuration covers every volume.

**S3 exposure follows AWS as it is today.** Since April 2023 every new bucket has all four Block Public Access settings on and ACLs disabled, however it is created ([AWS's announcement](https://aws.amazon.com/about-aws/whats-new/2022/12/amazon-s3-automatically-enable-block-public-access-disable-access-control-lists-buckets-april-2023/)). So a public ACL (a canned `public-read`, `public-read-write` or `authenticated-read`, or a grant to the AllUsers or AuthenticatedUsers group) takes effect only when the configuration enables ACLs (`aws_s3_bucket_ownership_controls` with `ObjectWriter` or `BucketOwnerPreferred`) and turns `block_public_acls` and `ignore_public_acls` off (an `aws_s3_bucket_public_access_block`, whose arguments default to `false`). A public bucket policy takes effect only when `block_public_policy` and `restrict_public_buckets` are off. An `aws_s3_account_public_access_block` in the configuration with the matching setting on blocks it for every bucket. A bucket created before 2023 and imported, or an account or organization setting made outside the files, is not visible here.

"Public" for a policy is AWS's own definition ([the meaning of "public"](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html#access-control-block-public-access-policy-status), `frame/iac/aws_policy.py`, the condition keys in `frame/iac/data/aws-public-policy.toml`): a statement that allows something is public unless it is limited to a fixed principal or to fixed values of the listed condition keys (`aws:SourceIp` no broader than /8, `aws:SourceVpc`, `aws:SourceArn`, ...; an `IfExists` operator, a wildcard or a policy variable does not limit it). A policy with a Deny statement that would otherwise be public is undecided, since AWS weighs denies. Policies are read from `jsonencode(...)`, a JSON string or heredoc, or a `data "aws_iam_policy_document"` (the provider's mapping of its blocks); parts known only at apply time leave the answer undecided only when the rule reads them (AWS's public rule never reads `Resource`).

Relations between resources (this public access block is for that bucket) are equalities between their `id`s, decided by Z3 with the facts in `frame/iac/data/terraform-facts.toml`: two resources of one type have different ids, and an S3 bucket's id is its name.

On TerraGoat these policies report the same resources as checkov's equivalent checks (CKV_AWS_24, 25, 277, 17, 16, 3; for S3 and IAM, CKV_AWS_20, 57, 62 and 1 report nothing there either). On terraform-aws-rds both report the same two databases; checkov also reports two inside a wrapper module whose `for_each` is empty by default (there are no such instances), and Frame leaves the read replica undecided (its source database comes from a module output that may be null).

**CloudFormation.** A YAML or JSON template (`AWSTemplateFormatVersion`, or `Resources` whose entries have `AWS::`-style types) is read as a deployment that takes every parameter's `Default` would see it (`frame/iac/cloudformation.py`). YAML is read as YAML 1.1 without the timestamp tag, as [CloudFormation reads it](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-formats.html) (a bare `yes` is true; `2010-09-09` is a string). The intrinsic functions are evaluated as the template reference defines them when their inputs are known: `Ref` to a parameter (its default, as a string; list types split), `Fn::Sub`, `Fn::Join`, `Fn::Select`, `Fn::Split`, `Fn::FindInMap`, `Fn::Base64`, `Fn::If`, and the `Conditions` (a resource whose condition is false is not created; `AWS::NoValue` removes a property). A resource's physical id (`Ref`), `Fn::GetAtt`, `Fn::ImportValue`, pseudo parameters and a parameter without a default are unknown; a tag that is not CloudFormation's (`!Rain::Embed`) makes its value unknown; a transform's additions are not read (a warning names the template). The AWS pack (`packs/data/cloudformation/aws.toml`) has the same seven policies as Terraform's, with CloudFormation's property names; a Block Public Access setting left out of a written `PublicAccessBlockConfiguration` is unknown, since its default is not documented (`data/cloudformation-facts.toml`).

On the 280 templates of aws-cloudformation/aws-cloudformation-templates Frame reads every template (warnings only for transforms). On the 44 where either tool reports something, every one of checkov's 31 equivalent findings is a Frame finding except a read replica, which takes its source's encryption; Frame adds four load balancer groups open on every port. A sample whose SSH default is `192.168.1.0/0` (all addresses, if AWS accepts a CIDR with host bits set) is undecided: whether AWS takes its network or refuses it is not documented.

**Helm.** A chart's `templates/` are Go templates. A template with no template actions (`{{`) renders as written and is checked; any other is skipped, with one warning per chart. Render the chart (`helm template ... > rendered.yaml`) and check the output.

## Findings

Each finding names the policy, its CWE, the resource (`Kind/namespace/name`), and the value that decides it: the line of `privileged: true`, or, for something missing, the container or securityContext that lacks it (`field` in JSON). `evidence` is `matched` when the files give every value the policy reads, and `solver-verified` when the solver proved the violation holds whatever the values the files leave open (Terraform variables, in a later release).

A violation that depends on values the files do not give (a base image's user, a build argument, a Terraform variable set at apply time, a CloudFormation parameter without a default) is **undecided**: listed with what it depends on (`depends_on` in JSON, `undecided:` lines in text), never reported as a finding.

`frame: ignore[<policy id or CWE>]` on the finding's line, or on a comment line above it, suppresses it (`suppressed` in JSON). `.frame.toml`'s `exclude`, `disable`, `packs`, `min_severity` and `fail_on` apply. Exit status: 0 clean, 1 a finding at or above `--fail-on` (default high), 2 the command could not run.

## Writing policies

Policies are packs ([coverage.md](coverage.md#teach-it-your-own-framework)) whose `language` is an infrastructure format, holding only `[[policy]]` entries. Put one in `.frame/packs/`, list it under `packs` in `.frame.toml`, or pass `--pack PATH`; `frame packs check FILE` validates it. A knowledge-base pack of the same name replaces the built-in one.

```toml
[pack]
name = "acme"
language = "kubernetes"

[[policy]]
id = "acme-memory-limit"
title = "Container has no memory limit"
severity = "medium"                       # critical high medium low info
cwe = "CWE-770"
when = '''some c in containers: absent(c.resources.limits.memory)'''
references = ["https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"]
```

`when` is the violation, a formula over the resource:

| Form | Meaning |
|---|---|
| `a == b`, `!=`, `<`, `<=`, `>`, `>=` | comparison (numbers, strings, booleans; `1 == true` is false) |
| `x in ["a", "b"]`, `x not in [...]`, `x in path.to.list` | membership |
| `present(p)`, `absent(p)` | whether a field has a value (`null` is none) |
| `starts_with(x, "prefix")` | string prefix |
| `number(x)` | x as a number, a decimal string included (CloudFormation's parameter values are strings) |
| `internet(c)`, `internet(c, 4)` | CIDR or address c contains an address the internet can send from (of IP version 4 or 6) |
| `name(a, b)` | a `[[define]]` of the pack, inlined |
| `default(p, v)` | p's value, or v when p is missing |
| `and`, `or`, `not`, `( )` | as usual |
| `some x in p: ...`, `every x in p: ...` | over a list; `some (k, v) in p: ...` over a map's entries; `p + q` concatenates |

The body of `some`/`every` extends as far right as it can; parenthesise to stop it. A comparison with a missing value is false, `==` and `!=` alike, so say what a missing field means with `default(...)`: the Kubernetes API's zero values (`false`, `0`, `""`) for its fields.

A pack can name a formula it uses more than once:

```toml
[[define]]
name = "tcp_port"
params = ["p", "from", "to", "port"]
body = '''p in ["-1", "all", -1] or (p in ["tcp", "6", 6] and from <= port and to >= port)'''
```

`tcp_port(r.protocol, r.from_port, r.to_port, 22)` then stands for the body with the paths (or literals) substituted. A define may call the defines before it.

Paths start at a resource's views. Every resource has `self` (the whole document; for a Dockerfile, the build stage: `final`, `from` with `image`/`tag`/`digest`/`stage`/`scratch`/`external`, `user`, `user_set`, `instructions` with `cmd`, `args`, `flags`, `sources`/`dest`, `vars` with `key`/`value`/`credential`, and `preamble` for the ARGs before the first FROM, in `frame/iac/dockerfile.py`; for Terraform, the resource's arguments, nested blocks as lists, and `id`; for CloudFormation, its `Properties` and `Ref`). A Terraform resource can also look at the other resources of its root module: `some d in resources["aws_ebs_encryption_by_default"]: d.enabled == true`. A resource with a `policy` argument (at any depth) also has `policy_public` and `policy_admin` beside it: true or false when the document is known, else unknown. A Kubernetes workload also has `pod` (its PodSpec), `podmeta` (the pod's metadata) and the collection `containers` (init, regular and ephemeral containers). A policy applies to the resources that have every view it names; `resources = ["Deployment", "Stateful*"]` narrows it by type. `overrides = ["other-id"]` replaces another policy on a resource where both hold. An unknown key, view or severity is an error that names the file and the policy.

## How a policy is decided

The formula is encoded in Z3 over the resource's values. A value the files give is a constant; a value they do not (a Terraform variable without a value, an attribute another resource computes) is one Z3 constant per value, so the same unknown in two places is the same value. A formula over known values folds to true or false without the solver. Otherwise, with C the facts the configuration states about its unknowns:

- the violation is reported when C entails it (`unsat(C & not V)`): it holds whatever the unknowns are;
- it is undecided when it is merely possible (`sat(C & V)`);
- it passes when it is impossible.

The paths that decide the result are kept, so a finding points at the line of the container or value that causes it.
