---
id: host-namespaces
title: Host Namespace
---

# Host Namespace

## Description
Disallows sharing of host PID and IPC namespaces by pod containers. Corresponds to the `hostPID` and `hostIPC` fields in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spsphostnamespace
  annotations:
    metadata.gatekeeper.sh/title: "Host Namespace"
    metadata.gatekeeper.sh/version: 1.0.1
    description: >-
      Disallows sharing of host PID and IPC namespaces by pod containers.
      Corresponds to the `hostPID` and `hostIPC` fields in a PodSecurityPolicy.
      For more information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces
spec:
  crd:
    spec:
      names:
        kind: K8sPSPHostNamespace
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Disallows sharing of host PID and IPC namespaces by pod containers.
            Corresponds to the `hostPID` and `hostIPC` fields in a PodSecurityPolicy.
            For more information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spsphostnamespace

        import data.lib.exclude_update.is_update

        violation[{"msg": msg, "details": {}}] {
            # spec.hostPID and spec.hostIPC fields are immutable.
            not is_update(input.review)

            input_share_hostnamespace(input.review.object)
            msg := sprintf("Sharing the host namespace is not allowed: %v", [input.review.object.metadata.name])
        }

        input_share_hostnamespace(o) {
            o.spec.hostPID
        }
        input_share_hostnamespace(o) {
            o.spec.hostIPC
        }
      libs:
        - |
          package lib.exclude_update

          is_update(review) {
              review.operation == "UPDATE"
          }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-namespaces/template.yaml
```
## Examples
<details>
<summary>host-namespace</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostNamespace
metadata:
  name: psp-host-namespace
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-namespaces/samples/psp-host-namespace/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-namespace-allowed
  labels:
    app: nginx-host-namespace
spec:
  hostPID: false
  hostIPC: false
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-namespaces/samples/psp-host-namespace/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-namespace-disallowed
  labels:
    app: nginx-host-namespace
spec:
  hostPID: true
  hostIPC: true
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-namespaces/samples/psp-host-namespace/example_disallowed.yaml
```

</details>


</details>