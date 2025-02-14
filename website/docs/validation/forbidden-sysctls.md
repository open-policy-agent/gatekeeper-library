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
    metadata.gatekeeper.sh/version: 1.2.0
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
      code:
      - engine: K8sNativeValidation
        source:
          variables:
          - name: isUpdate
            expression: has(request.operation) && request.operation == "UPDATE"
          - name: sysctls
            expression: '!has(variables.anyObject.spec.securityContext) ? [] : !has(variables.anyObject.spec.securityContext.sysctls) ? [] : variables.anyObject.spec.securityContext.sysctls'
          - name: allowedSysctlPrefixes
            expression: |
              !has(variables.params.allowedSysctls) ? [] : variables.params.allowedSysctls.filter(sysctl, sysctl.endsWith("*")).map(sysctl, string(sysctl).replace("*", ""))
          - name: allowedSysctlExplicit
            expression: |
              !has(variables.params.allowedSysctls) ? [] : 
                variables.params.allowedSysctls.filter(sysctl, !sysctl.endsWith("*"))
          - name: forbiddenSysctlPrefixes
            expression: |
              !has(variables.params.forbiddenSysctls) ? [] : variables.params.forbiddenSysctls.filter(sysctl, sysctl.endsWith("*")).map(sysctl, string(sysctl).replace("*", ""))
          - name: forbiddenSysctlExplicit
            expression: |
              !has(variables.params.forbiddenSysctls) ? [] : 
                variables.params.forbiddenSysctls.filter(sysctl, !sysctl.endsWith("*"))
          - name: allowedSysctlsString
            expression: |
              !has(variables.params.allowedSysctls) ? "unspecified" : size(variables.params.allowedSysctls) == 0 ? "empty" : variables.params.allowedSysctls.join(", ")
          - name: violatingSysctls
            expression: |
              (variables.sysctls.filter(sysctl,
                (sysctl.name in variables.forbiddenSysctlExplicit ||
                variables.forbiddenSysctlPrefixes.exists(fsp, string(sysctl.name).startsWith(fsp))) ||
                (has(variables.params.allowedSysctls) &&
                !(sysctl.name in variables.allowedSysctlExplicit) &&
                !variables.allowedSysctlPrefixes.exists(asp, string(sysctl.name).startsWith(asp)))))
          validations:
          - expression: 'variables.isUpdate || size(variables.violatingSysctls) == 0'
            messageExpression: '"The sysctl is not allowed for pod: " + variables.anyObject.metadata.name + ", forbidden: " + variables.params.forbiddenSysctls.join(", ") + ", allowed: " + variables.allowedSysctlsString'
      - engine: Rego
        source:
          rego: |
            package k8spspforbiddensysctls

            import data.lib.exclude_update.is_update

            # Block if forbidden
            violation[{"msg": msg, "details": {}}] {
                # spec.securityContext.sysctls field is immutable.
                not is_update(input.review)

                sysctl := input.review.object.spec.securityContext.sysctls[_].name
                forbidden_sysctl(sysctl)
                msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.forbiddenSysctls])
            }

            # Block if not explicitly allowed
            violation[{"msg": msg, "details": {}}] {
                not is_update(input.review)
                sysctl := input.review.object.spec.securityContext.sysctls[_].name
                not allowed_sysctl(sysctl)
                allowmsg := allowed_sysctl_string()
                msg := sprintf("The sysctl %v is not explicitly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.review.object.metadata.name, allowmsg])
            }

            # * may be used to forbid all sysctls
            forbidden_sysctl(_) {
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
            allowed_sysctl(_) {
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

            allowed_sysctl(_) {
                not input.parameters.allowedSysctls
            }
            allowed_sysctl_string() = out {
                not input.parameters.allowedSysctls
                out = "unspecified"
            }
            allowed_sysctl_string() = out {
                out = input.parameters.allowedSysctls
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/template.yaml
```
## Examples
<details>
<summary>forbidden-sysctls</summary>

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
  name: nginx-forbidden-sysctls-allowed
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


</details><details>
<summary>forbidden-sysctls-wildcard</summary>

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
    - "*" # * forbid all sysctls
    allowedSysctls:
    - "*" # allows all sysctls. allowedSysctls is optional.

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/samples/psp-forbidden-sysctls/constraint2.yaml
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
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-forbidden-sysctls-allowed
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


</details><details>
<summary>forbidden-sysctls3</summary>

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
    - "net.*"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/samples/psp-forbidden-sysctls/constraint3.yaml
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
  name: nginx-forbidden-sysctls-allowed
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


</details><details>
<summary>forbidden-sysctls4-empty-allowedSysctls</summary>

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
    allowedSysctls: [] # empty allowedSysctls means all sysctls are forbidden

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/samples/psp-forbidden-sysctls/constraint4.yaml
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
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-forbidden-sysctls-allowed
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


</details><details>
<summary>forbidden-sysctls5-unspecified-allowedSysctls</summary>

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
    # unspecified allowedSysctls will not place any restrictions

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/samples/psp-forbidden-sysctls/constraint5.yaml
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
  name: nginx-forbidden-sysctls-allowed
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


</details>