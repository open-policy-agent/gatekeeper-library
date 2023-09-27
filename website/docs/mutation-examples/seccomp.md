---
id: seccomp
title: seccomp
---

# seccomp

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/seccomp/samples/mutation-securityContext.yaml
```
## Mutation Examples
```yaml
apiVersion: mutations.gatekeeper.sh/v1alpha1
kind: Assign
metadata:
  name: k8spspseccompcontext
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  match:
    scope: Namespaced
    kinds:
    - apiGroups: ["*"]
      kinds: ["Pod"]
  location: "spec.securityContext.seccompProfile.type"
  parameters:
    pathTests:
    - subPath: "spec.securityContext.seccompProfile.type"
      condition: MustNotExist
    assign:
      value: RuntimeDefault

```