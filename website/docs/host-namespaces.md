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

        violation[{"msg": msg, "details": {}}] {
            input_share_hostnamespace(input.review.object)
            msg := sprintf("Sharing the host namespace is not allowed: %v", [input.review.object.metadata.name])
        }

        input_share_hostnamespace(o) {
            o.spec.hostPID
        }
        input_share_hostnamespace(o) {
            o.spec.hostIPC
        }

```

## Examples
<details>
<summary>host-namespace</summary><blockquote>

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

</details>


</blockquote></details>