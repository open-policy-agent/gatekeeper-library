---
id: users
title: users
---

# users

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/users/samples/mutation-fsGroup.yaml
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/users/samples/mutation-mustRunAsNonRoot.yaml
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/users/samples/mutation-runAsGroup.yaml
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/users/samples/mutation-runAsUser.yaml
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/users/samples/mutation-supplementalGroups.yaml
```
## Mutation Examples
```yaml
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spspfsGroup
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.securityContext.fsGroup"
  parameters:
    pathTests:
    - subPath: "spec.securityContext.fsGroup"
      condition: MustNotExist
    assign:
      value: 3000
---
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spsprunasnonroot
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.containers[name:*].securityContext.runAsNonRoot"
  parameters:
    pathTests:
      - subPath: "spec.containers[name:*].securityContext.runAsNonRoot"
        condition: MustNotExist
    assign:
      value: true
---
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spsprunasnonroot-init
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.initContainers[name:*].securityContext.runAsNonRoot"
  parameters:
    pathTests:
      - subPath: "spec.initContainers[name:*].securityContext.runAsNonRoot"
        condition: MustNotExist
    assign:
      value: true
---
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spsprunasgroup
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.containers[name:*].securityContext.runAsGroup"
  parameters:
    pathTests:
    - subPath: "spec.containers[name:*].securityContext.runAsGroup"
      condition: MustNotExist
    assign:
      value: 2000
---
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spsprunasgroup-init
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.initContainers[name:*].securityContext.runAsGroup"
  parameters:
    pathTests:
    - subPath: "spec.initContainers[name:*].securityContext.runAsGroup"
      condition: MustNotExist
    assign:
      value: 2000
---
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spsprunasuser
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.containers[name:*].securityContext.runAsUser"
  parameters:
    pathTests:
    - subPath: "spec.containers[name:*].securityContext.runAsUser"
      condition: MustNotExist
    assign:
      value: 1000
---
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spsprunasuser-init
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: "spec.initContainers[name:*].securityContext.runAsUser"
  parameters:
    pathTests:
    - subPath: "spec.initContainers[name:*].securityContext.runAsUser"
      condition: MustNotExist
    assign:
      value: 1000
---
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