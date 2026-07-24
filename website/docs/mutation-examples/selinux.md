---
id: selinux
title: selinux
---

# selinux

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/mutation/pod-security-policy/selinux/samples/mutation.yaml
```
## Mutation Examples
```yaml
apiVersion: mutations.gatekeeper.sh/v1
kind: Assign
metadata:
  name: k8spspselinux
spec:
  applyTo:
  - groups: [""]
    kinds: ["Pod"]
    versions: ["v1"]
  location: spec.containers[name:*].securityContext.seLinuxOptions
  parameters:
    pathTests:
    - subPath: spec.containers[name:*].securityContext.seLinuxOptions
      condition: MustNotExist
    assign:
      value:
        level: s1:c234,c567
        user: sysadm_u
        role: sysadm_r
        type: svirt_lxc_net_t

```