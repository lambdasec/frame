# A shop's infrastructure: Kubernetes manifests, Dockerfiles and Terraform

- `k8s/web.yaml`: the storefront, an ordinary Deployment with no security settings.
- `k8s/log-agent.yaml`: a log collector DaemonSet that reads the node's `/var/log`, on the host network, with `SYS_ADMIN`.
- `k8s/api.yaml`: the API, hardened to the Restricted profile.
- `k8s/debug.yaml`: a break-glass debug pod, privileged on purpose, its findings suppressed.
- `chart/`: a Helm chart for a worker.
- `images/`: the Dockerfiles of the web, log agent and API images.
- `terraform/`: the AWS network and database, with `terraform.tfvars`.
- `.frame/packs/acme.toml`: the platform team's own rule, that every container has a memory limit.

```console
$ frame iac .
images/log-agent/Dockerfile:11: [medium] docker-root-user (CWE-250) images/log-agent/Dockerfile stage 1: The image runs as root [user]
images/web/Dockerfile:8: [low] docker-floating-base-image (CWE-829) images/web/Dockerfile stage 1: Base image is not pinned (no tag, or latest, and no digest) [from.external]
images/web/Dockerfile:8: [low] docker-user-not-set (CWE-250) images/web/Dockerfile stage 1: The image never sets a user, so it runs as the base image's (root for most) [from.scratch]
images/web/Dockerfile:9: [medium] docker-add-unverified-download (CWE-494) images/web/Dockerfile stage 1: ADD downloads a remote file without a checksum [instructions[0].sources[0]]
k8s/debug.yaml:14: [medium] k8s-allow-privilege-escalation (CWE-269) Pod/ops/node-debug: Container may gain more privileges than its parent process [spec.containers[0].securityContext]
k8s/log-agent.yaml:13: [high] k8s-host-namespaces (CWE-668) DaemonSet/ops/log-agent: Pod shares the host's network, PID or IPC namespace [spec.template.spec.hostNetwork]
k8s/log-agent.yaml:15: [medium] acme-memory-limit (CWE-770) DaemonSet/ops/log-agent: Container has no memory limit [spec.template.spec.containers[0]]
k8s/log-agent.yaml:19: [high] k8s-capabilities-restricted (CWE-250) DaemonSet/ops/log-agent: Container does not drop ALL capabilities, or adds one other than NET_BIND_SERVICE [spec.template.spec.containers[0].securityContext.capabilities] (also k8s-capabilities-baseline)
k8s/log-agent.yaml:24: [high] k8s-host-volume-types (CWE-668) DaemonSet/ops/log-agent: Pod mounts a volume type outside the restricted set [spec.template.spec.volumes[0].hostPath] (also k8s-host-path-volumes)
k8s/web.yaml:15: [medium] k8s-run-as-non-root (CWE-250) Deployment/shop/web: Container may run as root [spec.template.spec.containers[0]]
...
terraform/database.tf:7: [high] aws-rds-public (CWE-284) aws_db_instance.orders: Database instance has a public endpoint [publicly_accessible]
terraform/network.tf:21: [high] aws-sg-admin-from-internet (CWE-284) aws_security_group.bastion: Security group lets the internet reach SSH or RDP [ingress[0].cidr_blocks[0]]

Infrastructure: 16 resource(s) in dockerfile: 3 file(s), kubernetes: 4 file(s), terraform: 2 file(s); 21 finding(s), 2 suppressed, 2 undecided (depend on values the files do not give)
undecided: images/web/Dockerfile:8 docker-root-user images/web/Dockerfile stage 1 (depends on the user of nginx)
undecided: terraform/network.tf:42 aws-sg-admin-from-internet aws_vpc_security_group_ingress_rule.partner_ssh (depends on var.partner_cidr)
warning: chart: Helm chart with 1 template(s) not checked (render it with `helm template` and scan the output)
```

## The Kubernetes manifests

The log agent breaks the Baseline profile three ways, each pointing at its line: the host network (line 13), `SYS_ADMIN` (line 19), and the `hostPath` volume (line 24). The checks are the Pod Security admission controller's, so a cluster that enforces `pod-security.kubernetes.io/enforce: baseline` would reject this DaemonSet for the same three reasons.

`SYS_ADMIN` breaks two checks, the Baseline one (a capability outside the runtime's default set) and its Restricted replacement (drop ALL, add at most NET_BIND_SERVICE). It is reported once, as the Restricted check with the Baseline check's high severity, and `also` names the one it replaced. The same goes for the `hostPath` volume.

The storefront breaks only the Restricted profile: nothing stops it running as root, gaining privileges, or running without a seccomp profile. A finding about something missing points at the container that lacks it (line 15). `api.yaml` sets those four things and has no finding.

The platform team's rule (`acme-memory-limit`) reports the log agent, the only container without a memory limit. It is a pack: a `[[policy]]` whose `when` says what a violation is, in Frame's policy language (`some c in containers: absent(c.resources.limits.memory)`). Packs in `.frame/packs/` load by themselves; `--pack PATH` adds others.

## The Dockerfiles

Each build stage is checked on its own, read as BuildKit reads the file.

- The log agent's image switches to `agent`, then back to root on line 11: whoever runs the container gets root, wherever the Kubernetes manifest forgets to set `runAsNonRoot`.
- The web image's final stage is `FROM nginx`: no tag means `latest`, whatever that is on the day of the build. It downloads the GeoIP database on line 9 with no `--checksum`, so a changed or tampered file goes into the image unnoticed.
- The web image never sets a user. Whether it then runs as root depends on the base image's own configuration, which is not in these files, so `docker-root-user` is **undecided** for it (counted in the summary, listed in `-f json` under `undecided`), and the weaker statement that is certain, `docker-user-not-set`, is reported instead. `nginx` does run as root.
- Its build stage (`node:22.11-bookworm`) is not the image that ships, so the user rules do not apply to it, and its tag pins it.
- The API image is pinned by digest and runs as UID 10001: nothing to report.

## The Terraform configuration

Terraform is read as a plan would see it, before anything is created: variables take the values the repository gives them, and what only exists once applied (an `id`, an `arn`) is unknown.

- The bastion's SSH rule reads `var.admin_cidr`. Its default is the office network, but `terraform.tfvars`, which Terraform loads by itself, sets it to `0.0.0.0/0`: SSH is open to the internet, reported on line 21. Remove the tfvars line and the finding goes.
- Whether a CIDR lets the internet in is decided over the address space with Z3, from IANA's registries of addresses that are not globally reachable: `0.0.0.0/1` counts, `100.64.0.0/10` (carrier-grade NAT) does not.
- The partner's SSH rule reads `var.partner_cidr`, which has no value in the files (it is given at apply time). The rule is open to the internet for some values and not for others, so it is **undecided**, and says what it depends on.
- The web group opens 443 to everyone, as a web server should: only SSH, RDP and every-port rules are reported.
- `orders` has a public endpoint (`publicly_accessible = true`). Its storage is encrypted, so only that is reported.
- The scratch volume sets no encryption, but `aws_ebs_encryption_by_default` in the same configuration turns it on for the account, so it is not reported.

## What is not reported

The debug pod is privileged and shares the host's PID namespace on purpose. Its two findings are suppressed by comments, on the line itself or on the comment line above (`# frame: ignore[k8s-privileged]`), and counted as `2 suppressed`. Its other findings are still reported: a suppression names the policy it silences. In a Dockerfile the comment goes on the line above (a `#` after an instruction is part of it).

The Helm template (`chart/templates/deployment.yaml`) uses template actions (`{{ .Values.image }}`), so its text is not the manifest the cluster sees. It is not checked, and the warning says so once per chart. Render it and check the result:

```bash
helm template worker chart/ > rendered.yaml && frame iac rendered.yaml
```

## In CI

The default `--fail-on high` fails on the high findings alone: the Baseline breaks, SSH open to the internet, and the public database:

```console
$ frame iac . --min-severity high
k8s/log-agent.yaml:13: [high] k8s-host-namespaces (CWE-668) DaemonSet/ops/log-agent: Pod shares the host's network, PID or IPC namespace [spec.template.spec.hostNetwork]
k8s/log-agent.yaml:19: [high] k8s-capabilities-restricted (CWE-250) DaemonSet/ops/log-agent: Container does not drop ALL capabilities, or adds one other than NET_BIND_SERVICE [spec.template.spec.containers[0].securityContext.capabilities] (also k8s-capabilities-baseline)
k8s/log-agent.yaml:24: [high] k8s-host-volume-types (CWE-668) DaemonSet/ops/log-agent: Pod mounts a volume type outside the restricted set [spec.template.spec.volumes[0].hostPath] (also k8s-host-path-volumes)
terraform/database.tf:7: [high] aws-rds-public (CWE-284) aws_db_instance.orders: Database instance has a public endpoint [publicly_accessible]
terraform/network.tf:21: [high] aws-sg-admin-from-internet (CWE-284) aws_security_group.bastion: Security group lets the internet reach SSH or RDP [ingress[0].cidr_blocks[0]]

Infrastructure: 16 resource(s) in dockerfile: 3 file(s), kubernetes: 4 file(s), terraform: 2 file(s); 5 finding(s), 2 suppressed, 2 undecided (depend on values the files do not give)
```

The exit status is 1. `-f sarif` writes the findings for GitHub code scanning, each with the line and a stable fingerprint; `frame scan . --iac` puts them beside the source scan's.

How the checks are decided, and how close they are to Kubernetes, BuildKit and HashiCorp's HCL themselves: [docs/iac.md](../../docs/iac.md).
