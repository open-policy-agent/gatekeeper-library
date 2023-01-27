---
id: seccomp
title: seccomp
---

# seccomp

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/seccomp/samples/mutation.yaml
```
## Mutation Examples
```yaml
apiVersion: mutations.gatekeeper.sh/v1alpha1
kind: AssignMetadata
metadata:
  name: k8spspseccomp
spec:
  match:
    scope: Namespaced
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
  location: metadata.annotations."seccomp.security.alpha.kubernetes.io/pod"
  parameters:
    assign:
      value: runtime/default

```