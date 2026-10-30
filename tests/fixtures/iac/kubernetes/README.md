# Kubernetes fixtures

- `pss/`: the Pod Security admission controller's test fixtures for Kubernetes v1.38, copied
  unchanged from kubernetes/kubernetes at f2a57ac2b9d3ea965421f0f72d1aa8b0dc6531e9
  (`staging/src/k8s.io/pod-security-admission/test/testdata`), Apache License 2.0,
  Copyright The Kubernetes Authors. `pass/` pods are admitted at their level, `fail/` pods are
  denied; each file name is the check it exercises.
- `real/kubernetes-goat/`: the scenario workloads of madhuakula/kubernetes-goat at
  723a0db478f050d173d23b4ce5044b65bce0bdd0 (MIT, `LICENSE` beside them), a deliberately insecure
  cluster.
- `real/microservices-demo/`: `kubernetes-manifests/` of GoogleCloudPlatform/microservices-demo
  at c7cb6d5bfd6ea3aed768634ebbcb98cb7a523712 (Apache License 2.0, `LICENSE` beside them).

`expected.tsv` in each is the upstream evaluator's verdict on every object
(tests/iac_real/psa).
