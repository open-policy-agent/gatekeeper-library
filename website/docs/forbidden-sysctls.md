---
id: forbidden-sysctls
title: Forbidden Sysctls
---

# Forbidden Sysctls

## Description
Controls the `sysctl` profile used by containers. Corresponds to the `allowedUnsafeSysctls` and `forbiddenSysctls` fields in a PodSecurityPolicy. When specified, any sysctl not in the `allowedSysctls` parameter is considered to be forbidden. The `forbiddenSysctls` parameter takes precedence over the `allowedSysctls` parameter. For more information, see https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspforbiddensysctls
  annotations:
    metadata.gatekeeper.sh/title: "Forbidden Sysctls"
    metadata.gatekeeper.sh/version: 1.1.0
    description: >-
      Controls the `sysctl` profile used by containers. Corresponds to the
      `allowedUnsafeSysctls` and `forbiddenSysctls` fields in a PodSecurityPolicy.
      When specified, any sysctl not in the `allowedSysctls` parameter is considered to be forbidden.
      The `forbiddenSysctls` parameter takes precedence over the `allowedSysctls` parameter.
      For more information, see https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/
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
            `allowedUnsafeSysctls` and `forbiddenSysctls` fields in a PodSecurityPolicy.
            When specified, any sysctl not in the `allowedSysctls` parameter is considered to be forbidden.
            The `forbiddenSysctls` parameter takes precedence over the `allowedSysctls` parameter.
            For more information, see https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/
          properties:
            allowedSysctls:
              type: array
              description: "An allow-list of sysctls. `*` allows all sysctls not listed in the `forbiddenSysctls` parameter."
              items:
                type: string
            forbiddenSysctls:
              type: array
              description: "A disallow-list of sysctls. `*` forbids all sysctls."
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspforbiddensysctls

        # Block if forbidden
        violation[{"msg": msg, "details": {}}] {
            sysctl := input.review.object.spec.securityContext.sysctls[_].name
            forbidden_sysctl(sysctl)
            msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.forbiddenSysctls])
        }

        # Block if not explicitly allowed
        violation[{"msg": msg, "details": {}}] {
            sysctl := input.review.object.spec.securityContext.sysctls[_].name
            not allowed_sysctl(sysctl)
            msg := sprintf("The sysctl %v is not explictly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.allowedSysctls])
        }

        # * may be used to forbid all sysctls
        forbidden_sysctl(sysctl) {
            input.parameters.forbiddenSysctls[_] == "*"
        }

        forbidden_sysctl(sysctl) {
            input.parameters.forbiddenSysctls[_] == sysctl
        }

        forbidden_sysctl(sysctl) {
            forbidden := input.parameters.forbiddenSysctls[_]
            endswith(forbidden, "*")
            startswith(sysctl, trim_suffix(forbidden, "*"))
        }

        # * may be used to allow all sysctls
        allowed_sysctl(sysctl) {
            input.parameters.allowedSysctls[_] == "*"
        }

        allowed_sysctl(sysctl) {
            input.parameters.allowedSysctls[_] == sysctl
        }

        allowed_sysctl(sysctl) {
            allowed := input.parameters.allowedSysctls[_]
            endswith(allowed, "*")
            startswith(sysctl, trim_suffix(allowed, "*"))
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/template.yaml
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
    allowedSysctls:
    - "*" # allows all sysctls. allowedSysctls is optional.

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/samples/psp-forbidden-sysctls/constraint.yaml
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

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/samples/psp-forbidden-sysctls/example_disallowed.yaml
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

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/samples/psp-forbidden-sysctls/example_allowed.yaml
```

</details>


</blockquote></details>