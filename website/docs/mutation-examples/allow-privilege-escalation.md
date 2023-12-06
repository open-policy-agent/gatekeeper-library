---
id: allow-privilege-escalation
title: allow-privilege-escalation
---

# allow-privilege-escalation

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/allow-privilege-escalation/samples/mutation.yaml
```
## Mutation Examples
```yaml
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spspdefaultallowprivilegeescalation
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.containers[name:*].securityContext.allowPrivilegeEscalation"
  parameters:
    pathTests:
    - subPath: "spec.containers[name:*].securityContext.allowPrivilegeEscalation"
      condition: MustNotExist
    assign:
      value: false
---
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spspdefaultallowprivilegeescalation-init
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.initContainers[name:*].securityContext.allowPrivilegeEscalation"
  parameters:
    pathTests:
    - subPath: "spec.initContainers[name:*].securityContext.allowPrivilegeEscalation"
      condition: MustNotExist
    assign:
      value: false
---
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spspdefaultallowprivilegeescalation-ephemeral
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.ephemeralContainers[name:*].securityContext.allowPrivilegeEscalation"
  parameters:
    pathTests:
    - subPath: "spec.ephemeralContainers[name:*].securityContext.allowPrivilegeEscalation"
      condition: MustNotExist
    assign:
      value: false

```