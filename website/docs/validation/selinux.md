---
id: selinux
title: SELinux V2
---

# SELinux V2

## Description
Defines an allow-list of seLinuxOptions configurations for pod containers. Corresponds to a PodSecurityPolicy requiring SELinux configs. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#selinux

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspselinuxv2
  annotations:
    metadata.gatekeeper.sh/title: "SELinux V2"
    metadata.gatekeeper.sh/version: 1.0.3
    description: >-
      Defines an allow-list of seLinuxOptions configurations for pod
      containers. Corresponds to a PodSecurityPolicy requiring SELinux configs.
      For more information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#selinux
spec:
  crd:
    spec:
      names:
        kind: K8sPSPSELinuxV2
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Defines an allow-list of seLinuxOptions configurations for pod
            containers. Corresponds to a PodSecurityPolicy requiring SELinux configs.
            For more information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#selinux
          properties:
            exemptImages:
              description: >-
                Any container that uses an image that matches an entry in this list will be excluded
                from enforcement. Prefix-matching can be signified with `*`. For example: `my-image-*`.

                It is recommended that users use the fully-qualified Docker image name (e.g. start with a domain name)
                in order to avoid unexpectedly exempting images from an untrusted repository.
              type: array
              items:
                type: string
            allowedSELinuxOptions:
              type: array
              description: "An allow-list of SELinux options configurations."
              items:
                type: object
                description: "An allowed configuration of SELinux options for a pod container."
                properties:
                  level:
                    type: string
                    description: "An SELinux level."
                  role:
                    type: string
                    description: "An SELinux role."
                  type:
                    type: string
                    description: "An SELinux type."
                  user:
                    type: string
                    description: "An SELinux user."
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspselinux

        import data.lib.exclude_update.is_update
        import data.lib.exempt_container.is_exempt

        # Disallow top level custom SELinux options
        violation[{"msg": msg, "details": {}}] {
            # spec.securityContext.seLinuxOptions field is immutable.
            not is_update(input.review)

            has_field(input.review.object.spec.securityContext, "seLinuxOptions")
            not input_seLinuxOptions_allowed(input.review.object.spec.securityContext.seLinuxOptions)
            msg := sprintf("SELinux options is not allowed, pod: %v. Allowed options: %v", [input.review.object.metadata.name, input.parameters.allowedSELinuxOptions])
        }
        # Disallow container level custom SELinux options
        violation[{"msg": msg, "details": {}}] {
            # spec.containers.securityContext.seLinuxOptions field is immutable.
            not is_update(input.review)

            c := input_security_context[_]
            not is_exempt(c)
            has_field(c.securityContext, "seLinuxOptions")
            not input_seLinuxOptions_allowed(c.securityContext.seLinuxOptions)
            msg := sprintf("SELinux options is not allowed, pod: %v, container: %v. Allowed options: %v", [input.review.object.metadata.name, c.name, input.parameters.allowedSELinuxOptions])
        }

        input_seLinuxOptions_allowed(options) {
            params := input.parameters.allowedSELinuxOptions[_]
            field_allowed("level", options, params)
            field_allowed("role", options, params)
            field_allowed("type", options, params)
            field_allowed("user", options, params)
        }

        field_allowed(field, options, params) {
            params[field] == options[field]
        }
        field_allowed(field, options, _) {
            not has_field(options, field)
        }

        input_security_context[c] {
            c := input.review.object.spec.containers[_]
            has_field(c.securityContext, "seLinuxOptions")
        }
        input_security_context[c] {
            c := input.review.object.spec.initContainers[_]
            has_field(c.securityContext, "seLinuxOptions")
        }
        input_security_context[c] {
            c := input.review.object.spec.ephemeralContainers[_]
            has_field(c.securityContext, "seLinuxOptions")
        }

        # has_field returns whether an object has a field
        has_field(object, field) = true {
            object[field]
        }
      libs:
        - |
          package lib.exclude_update

          is_update(review) {
              review.operation == "UPDATE"
          }
        - |
          package lib.exempt_container

          is_exempt(container) {
              exempt_images := object.get(object.get(input, "parameters", {}), "exemptImages", [])
              img := container.image
              exemption := exempt_images[_]
              _matches_exemption(img, exemption)
          }

          _matches_exemption(img, exemption) {
              not endswith(exemption, "*")
              exemption == img
          }

          _matches_exemption(img, exemption) {
              endswith(exemption, "*")
              prefix := trim_suffix(exemption, "*")
              startswith(img, prefix)
          }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/selinux/template.yaml
```
## Examples
<details>
<summary>require-matching-selinux-options</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPSELinuxV2
metadata:
  name: psp-selinux-v2
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowedSELinuxOptions:
      - level: s0:c123,c456
        role: object_r
        type: svirt_sandbox_file_t
        user: system_u

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/selinux/samples/psp-selinux-v2/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
    name: nginx-selinux-disallowed
    labels:
        app: nginx-selinux
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      seLinuxOptions:
        level: s1:c234,c567
        user: sysadm_u
        role: sysadm_r
        type: svirt_lxc_net_t

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/selinux/samples/psp-selinux-v2/example_disallowed.yaml
```

</details>
<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
    name: nginx-selinux-allowed
    labels:
        app: nginx-selinux
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      seLinuxOptions:
        level: s0:c123,c456
        role: object_r
        type: svirt_sandbox_file_t
        user: system_u

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/selinux/samples/psp-selinux-v2/example_allowed.yaml
```

</details>
<details>
<summary>disallowed-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
    name: nginx-selinux-disallowed
    labels:
        app: nginx-selinux
spec:
  ephemeralContainers:
  - name: nginx
    image: nginx
    securityContext:
      seLinuxOptions:
        level: s1:c234,c567
        user: sysadm_u
        role: sysadm_r
        type: svirt_lxc_net_t

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/selinux/samples/psp-selinux-v2/disallowed_ephemeral.yaml
```

</details>


</details>