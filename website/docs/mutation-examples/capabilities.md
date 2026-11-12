---
id: capabilities
title: capabilities
---

# capabilities

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/capabilities/samples/mutation-assign.yaml
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/capabilities/samples/mutation-modifyset.yaml
```
## Mutation Examples
```yaml
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spspcapabilities
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.containers[name:*].securityContext.capabilities.add"
  parameters:
    assign:
      value: ["NEW_CAPABILITY"] # default add capability
---
apiVersion: mutations.gatekeeper.sh/v1
kind: ModifySet
metadata:
  name: k8spspcapabilities
spec:
  applyTo:
    - groups: [""]
      versions: ["v1"]
      kinds: ["Pod"]
  match:
    scope: Namespaced
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  location: "spec.containers[name:*].securityContext.capabilities.add"
  parameters:
    operation: merge
    values:
      fromList: ["NEW_CAPABILITY"]

```