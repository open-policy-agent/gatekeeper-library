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
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spspseccomp
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: spec.securityContext.seccompProfile
  parameters:
    pathTests:
    - subPath: spec.securityContext.seccompProfile
      condition: MustNotExist
    assign:
      value:
        type: RuntimeDefault

```