---
id: forbidden-sysctls
title: Forbidden Sysctls
---

# Forbidden Sysctls

## Description
Controls the `sysctl` profile used by containers. Corresponds to the `forbiddenSysctls` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspforbiddensysctls
  annotations:
    metadata.gatekeeper.sh/title: "Forbidden Sysctls"
    description: >-
      Controls the `sysctl` profile used by containers. Corresponds to the
      `forbiddenSysctls` field in a PodSecurityPolicy. For more information,
      see https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/
spec:
  crd:
    spec:
      names:
        kind: K8sPSPForbiddenSysctls
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Controls the `sysctl` profile used by containers. Corresponds to the
            `forbiddenSysctls` field in a PodSecurityPolicy. For more information,
            see https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/
          properties:
            forbiddenSysctls:
              type: array
              description: "A disallow-list of sysctls. `*` forbids all sysctls."
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspforbiddensysctls

        violation[{"msg": msg, "details": {}}] {
            sysctl := input.review.object.spec.securityContext.sysctls[_].name
            forbidden_sysctl(sysctl)
            msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.forbiddenSysctls])
        }

        # * may be used to forbid all sysctls
        forbidden_sysctl(sysctl) {
            input.parameters.forbiddenSysctls[_] == "*"
        }

        forbidden_sysctl(sysctl) {
            input.parameters.forbiddenSysctls[_] == sysctl
        }

        forbidden_sysctl(sysctl) {
            startswith(sysctl, trim(input.parameters.forbiddenSysctls[_], "*"))
        }

```

## Examples
<details>
<summary>forbidden-sysctls</summary><blockquote>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPForbiddenSysctls
metadata:
  name: psp-forbidden-sysctls
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    forbiddenSysctls:
    # - "*" # * may be used to forbid all sysctls
    - kernel.*

```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-forbidden-sysctls-disallowed
  labels:
    app: nginx-forbidden-sysctls
spec:
  containers:
    - name: nginx
      image: nginx
  securityContext:
    sysctls:
      - name: kernel.msgmax
        value: "65536"
      - name: net.core.somaxconn
        value: "1024"

```

</details>
<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-forbidden-sysctls-disallowed
  labels:
    app: nginx-forbidden-sysctls
spec:
  containers:
    - name: nginx
      image: nginx
  securityContext:
    sysctls:
      - name: net.core.somaxconn
        value: "1024"

```

</details>


</blockquote></details>