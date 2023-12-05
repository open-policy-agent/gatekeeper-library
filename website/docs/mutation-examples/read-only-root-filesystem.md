---
id: read-only-root-filesystem
title: read-only-root-filesystem
---

# read-only-root-filesystem

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/read-only-root-filesystem/samples/mutation.yaml
```
## Mutation Examples
```yaml
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spspreadonlyrootfs
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.containers[name:*].securityContext.readOnlyRootFilesystem"
  parameters:
    pathTests:
    - subPath: "spec.containers[name:*].securityContext.readOnlyRootFilesystem"
      condition: MustNotExist
    assign:
      value: true

```