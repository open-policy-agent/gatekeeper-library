---
id: users
title: users
---

# users

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/users/samples/mutation-supplementalGroups.yaml
```
## Mutation Examples
```yaml
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spspsupplementalgroups
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.securityContext.supplementalGroups"
  parameters:
    pathTests:
    - subPath: "spec.securityContext.supplementalGroups"
      condition: MustNotExist
    assign:
      value: [3000]

```