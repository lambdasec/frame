# Ground truth for the Pod Security Standards pack

The Kubernetes Pod Security admission controller's own evaluator
(`k8s.io/pod-security-admission/policy`, the newest version of every check, Kubernetes v1.38),
run on the fixtures in `tests/fixtures/iac/kubernetes`. Its output is committed beside them as
`expected.tsv`, which `tests/test_iac_kubernetes.py` compares with Frame check for check.

```bash
cd tests/iac_real/psa
F=../../fixtures/iac/kubernetes
GOTOOLCHAIN=auto go run ./cmd/fixtures  $F/pss  > $F/pss/expected.tsv    # upstream's test fixtures
GOTOOLCHAIN=auto go run ./cmd/workloads $F/real > $F/real/expected.tsv   # real workloads
```

`cmd/fixtures` prints `file, level, denying reasons` per fixture; `cmd/workloads` decodes every
object of every YAML/JSON file with client-go's scheme, extracts the pod spec as the admission
controller does (`admission.DefaultPodSpecExtractor`) and prints `file, Kind/[namespace/]name,
level, denying reasons`. Objects the scheme cannot decode are skipped.

The evaluator runs on the decoded object; a cluster first applies the API's defaults. Where that
changes the answer, the test lists the case and Frame follows the cluster (a volume with no source
is defaulted to `emptyDir`).

To refresh the fixtures from a newer Kubernetes: copy
`staging/src/k8s.io/pod-security-admission/test/testdata/{baseline,restricted}/v1.NN` from
kubernetes/kubernetes, move the module requirements in `go.mod` to that release, update `v1.38`
in `cmd/fixtures/main.go`, `cmd/workloads/main.go` and the test, and rerun both commands.
