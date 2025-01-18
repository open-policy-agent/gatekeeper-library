---
id: proc-mount
title: Proc Mount
---

# Proc Mount

## Description
Controls the allowed `procMount` types for the container. Corresponds to the `allowedProcMountTypes` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#allowedprocmounttypes

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspprocmount
  annotations:
    metadata.gatekeeper.sh/title: "Proc Mount"
    metadata.gatekeeper.sh/version: 1.1.2
    description: >-
      Controls the allowed `procMount` types for the container. Corresponds to
      the `allowedProcMountTypes` field in a PodSecurityPolicy. For more
      information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#allowedprocmounttypes
spec:
  crd:
    spec:
      names:
        kind: K8sPSPProcMount
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Controls the allowed `procMount` types for the container. Corresponds to
            the `allowedProcMountTypes` field in a PodSecurityPolicy. For more
            information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#allowedprocmounttypes
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
            procMount:
              type: string
              description: >-
                Defines the strategy for the security exposure of certain paths
                in `/proc` by the container runtime. Setting to `Default` uses
                the runtime defaults, where `Unmasked` bypasses the default
                behavior.
              enum:
                - Default
                - Unmasked
  targets:
    - target: admission.k8s.gatekeeper.sh
      code:
      - engine: K8sNativeValidation
        source:
          variables:
          - name: containers
            expression: 'has(variables.anyObject.spec.containers) ? variables.anyObject.spec.containers : []'
          - name: initContainers
            expression: 'has(variables.anyObject.spec.initContainers) ? variables.anyObject.spec.initContainers : []'
          - name: ephemeralContainers
            expression: 'has(variables.anyObject.spec.ephemeralContainers) ? variables.anyObject.spec.ephemeralContainers : []'
          - name: exemptImagePrefixes
            expression: |
              !has(variables.params.exemptImages) ? [] :
                variables.params.exemptImages.filter(image, image.endsWith("*")).map(image, string(image).replace("*", ""))
          - name: exemptImageExplicit
            expression: |
              !has(variables.params.exemptImages) ? [] : 
                variables.params.exemptImages.filter(image, !image.endsWith("*"))
          - name: exemptImages
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(
                container,
                container.image in variables.exemptImageExplicit ||
                  variables.exemptImagePrefixes.exists(
                    exemption,
                    string(container.image).startsWith(exemption)
                  )
              ).map(container, container.image)
          - name: allowedProcMount
            expression: |
              !has(variables.params) ? "default" : 
                !has(variables.params.procMount) ? "default" : 
                  (variables.params.procMount.lowerAscii() == "default" || variables.params.procMount.lowerAscii() == "unmasked") ? variables.params.procMount.lowerAscii() : "default"
          - name: badContainers
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,
                !(container.image in variables.exemptImages) &&
                !(
                  (variables.allowedProcMount == "unmasked") ||
                  (variables.allowedProcMount == "default" && (!has(container.securityContext) || !has(container.securityContext.procMount) || container.securityContext.procMount == null || container.securityContext.procMount.lowerAscii() == "default"))
                )
              ).map(container, "ProcMount type is not allowed, container: " + container.name +". Allowed procMount types: " + variables.allowedProcMount)
          validations:
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.badContainers) == 0'
            messageExpression: 'variables.badContainers.join("\n")' 
      - engine: Rego
        source:
          rego: |
            package k8spspprocmount

            import data.lib.exclude_update.is_update
            import data.lib.exempt_container.is_exempt

            violation[{"msg": msg, "details": {}}] {
                # spec.containers.securityContext.procMount field is immutable.
                not is_update(input.review)

                c := input_containers[_]
                not is_exempt(c)
                allowedProcMount := get_allowed_proc_mount(input)
                not input_proc_mount_type_allowed(allowedProcMount, c)
                msg := sprintf("ProcMount type is not allowed, container: %v. Allowed procMount types: %v", [c.name, allowedProcMount])
            }

            input_proc_mount_type_allowed(allowedProcMount, c) {
                allowedProcMount == "default"
                lower(c.securityContext.procMount) == "default"
            }
            input_proc_mount_type_allowed(allowedProcMount, _) {
                allowedProcMount == "unmasked"
            }

            input_containers[c] {
                c := input.review.object.spec.containers[_]
                c.securityContext.procMount != null
            }
            input_containers[c] {
                c := input.review.object.spec.initContainers[_]
                c.securityContext.procMount != null
            }
            input_containers[c] {
                c := input.review.object.spec.ephemeralContainers[_]
                c.securityContext.procMount != null
            }

            get_allowed_proc_mount(arg) = out {
                not arg.parameters
                out = "default"
            }
            get_allowed_proc_mount(arg) = out {
                not arg.parameters.procMount
                out = "default"
            }
            get_allowed_proc_mount(arg) = out {
                arg.parameters.procMount
                not valid_proc_mount(arg.parameters.procMount)
                out = "default"
            }
            get_allowed_proc_mount(arg) = out {
                valid_proc_mount(arg.parameters.procMount)
                out = lower(arg.parameters.procMount)
            }

            valid_proc_mount(str) {
                lower(str) == "default"
            }
            valid_proc_mount(str) {
                lower(str) == "unmasked"
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/proc-mount/template.yaml
```
## Examples
<details>
<summary>default-proc-mount-required</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPProcMount
metadata:
  name: psp-proc-mount
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    procMount: Default
    exemptImages:
    - "safeimages.com/*"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/proc-mount/samples/psp-proc-mount/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-proc-mount-disallowed
  labels:
    app: nginx-proc-mount
spec:
  hostUsers: false
  containers:
  - name: nginx
    image: nginx
    securityContext:
      procMount: Unmasked #Default

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/proc-mount/samples/psp-proc-mount/example_disallowed.yaml
```

</details>
<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-proc-mount-allowed
  labels:
    app: nginx-proc-mount
spec:
  hostUsers: false
  containers:
  - name: nginx
    image: nginx
    securityContext:
      procMount: Default

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/proc-mount/samples/psp-proc-mount/example_allowed.yaml
```

</details>
<details>
<summary>example-allowed-missing</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-proc-mount-disallowed
  labels:
    app: nginx-proc-mount
spec:
  hostUsers: false
  containers:
  - name: no-proc-mount-value
    image: nginx
    securityContext:
      procMount: null
  - name: no-proc-mount
    image: nginx
    securityContext: {}
  - name: no-context
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/proc-mount/samples/psp-proc-mount/example_allowed_missing.yaml
```

</details>
<details>
<summary>disallowed-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-proc-mount-disallowed
  labels:
    app: nginx-proc-mount
spec:
  hostUsers: false
  ephemeralContainers:
  - name: nginx
    image: nginx
    securityContext:
      procMount: Unmasked #Default

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/proc-mount/samples/psp-proc-mount/disallowed_ephemeral.yaml
```

</details>
<details>
<summary>image-exempt-prefix-match</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-proc-mount-exempt-image
  labels:
    app: nginx-proc-mount
spec:
  hostUsers: false
  containers:
  - name: nginx
    image: safeimages.com/nginx
    securityContext:
      procMount: Unmasked #Default

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/proc-mount/samples/psp-proc-mount/example_allowed_exempt_image.yaml
```

</details>


</details>