# Infrastructure as code

`frame iac` reads the infrastructure files in a repository into one model of resources and decides each policy on each resource with Z3. This release reads Kubernetes manifests (checked against the Pod Security Standards) and Dockerfiles. Terraform, CloudFormation and Helm rendering follow ([roadmap](roadmap.md)).

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

**Helm.** A chart's `templates/` are Go templates. A template with no template actions (`{{`) renders as written and is checked; any other is skipped, with one warning per chart. Render the chart (`helm template ... > rendered.yaml`) and check the output.

## Findings

Each finding names the policy, its CWE, the resource (`Kind/namespace/name`), and the value that decides it: the line of `privileged: true`, or, for something missing, the container or securityContext that lacks it (`field` in JSON). `evidence` is `matched` when the files give every value the policy reads, and `solver-verified` when the solver proved the violation holds whatever the values the files leave open (Terraform variables, in a later release).

A violation that depends on values the files do not give (a base image's user, a build argument) is **undecided**: listed in `undecided` in JSON and counted in the summary, never reported as a finding.

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
| `default(p, v)` | p's value, or v when p is missing |
| `and`, `or`, `not`, `( )` | as usual |
| `some x in p: ...`, `every x in p: ...` | over a list; `some (k, v) in p: ...` over a map's entries; `p + q` concatenates |

The body of `some`/`every` extends as far right as it can; parenthesise to stop it. A comparison with a missing value is false, `==` and `!=` alike, so say what a missing field means with `default(...)`: the Kubernetes API's zero values (`false`, `0`, `""`) for its fields.

Paths start at a resource's views. Every resource has `self` (the whole document; for a Dockerfile, the build stage: `final`, `from` with `image`/`tag`/`digest`/`stage`/`scratch`/`external`, `user`, `user_set`, `instructions` with `cmd`, `args`, `flags`, `sources`/`dest`, `vars` with `key`/`value`/`credential`, and `preamble` for the ARGs before the first FROM, in `frame/iac/dockerfile.py`). A Kubernetes workload also has `pod` (its PodSpec), `podmeta` (the pod's metadata) and the collection `containers` (init, regular and ephemeral containers). A policy applies to the resources that have every view it names; `resources = ["Deployment", "Stateful*"]` narrows it by type. `overrides = ["other-id"]` replaces another policy on a resource where both hold. An unknown key, view or severity is an error that names the file and the policy.

## How a policy is decided

The formula is encoded in Z3 over the resource's values. A value the files give is a constant; a value they do not (a Terraform variable without a value, an attribute another resource computes) is one Z3 constant per value, so the same unknown in two places is the same value. A formula over known values folds to true or false without the solver. Otherwise, with C the facts the configuration states about its unknowns:

- the violation is reported when C entails it (`unsat(C & not V)`): it holds whatever the unknowns are;
- it is undecided when it is merely possible (`sat(C & V)`);
- it passes when it is impossible.

The paths that decide the result are kept, so a finding points at the line of the container or value that causes it.
