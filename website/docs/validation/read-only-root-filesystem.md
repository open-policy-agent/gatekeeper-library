---
id: read-only-root-filesystem
title: Read Only Root Filesystem
---

# Read Only Root Filesystem

## Description
Requires the use of a read-only root file system by pod containers. Corresponds to the `readOnlyRootFilesystem` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspreadonlyrootfilesystem
  annotations:
    metadata.gatekeeper.sh/title: "Read Only Root Filesystem"
    metadata.gatekeeper.sh/version: 1.1.1
    description: >-
      Requires the use of a read-only root file system by pod containers.
      Corresponds to the `readOnlyRootFilesystem` field in a
      PodSecurityPolicy. For more information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems
spec:
  crd:
    spec:
      names:
        kind: K8sPSPReadOnlyRootFilesystem
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Requires the use of a read-only root file system by pod containers.
            Corresponds to the `readOnlyRootFilesystem` field in a
            PodSecurityPolicy. For more information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems
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
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,
                container.image in variables.exemptImageExplicit ||
                variables.exemptImagePrefixes.exists(exemption, string(container.image).startsWith(exemption))).map(container, container.image)
          - name: badContainers
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,
                !(container.image in variables.exemptImages) && 
                (!has(container.securityContext) ||
                !has(container.securityContext.readOnlyRootFilesystem) ||
                container.securityContext.readOnlyRootFilesystem != true)
              ).map(container, container.name)
          validations:
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.badContainers) == 0'
            messageExpression: '"only read-only root filesystem container is allowed: " + variables.badContainers.join(", ")'
            
      - engine: Rego
        source:
          rego: |
            package k8spspreadonlyrootfilesystem

            import data.lib.exclude_update.is_update
            import data.lib.exempt_container.is_exempt

            violation[{"msg": msg, "details": {}}] {
                # spec.containers.readOnlyRootFilesystem field is immutable.
                not is_update(input.review)

                c := input_containers[_]
                not is_exempt(c)
                input_read_only_root_fs(c)
                msg := sprintf("only read-only root filesystem container is allowed: %v", [c.name])
            }

            input_read_only_root_fs(c) {
                not has_field(c, "securityContext")
            }
            input_read_only_root_fs(c) {
                not c.securityContext.readOnlyRootFilesystem == true
            }

            input_containers[c] {
                c := input.review.object.spec.containers[_]
            }
            input_containers[c] {
                c := input.review.object.spec.initContainers[_]
            }
            input_containers[c] {
                c := input.review.object.spec.ephemeralContainers[_]
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/template.yaml
```
## Examples
<details>
<summary>require-read-only-root-filesystem</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPReadOnlyRootFilesystem
metadata:
  name: psp-readonlyrootfilesystem
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    exemptImages:
    - "specialprogram"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/samples/psp-readonlyrootfilesystem/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-readonlyrootfilesystem-disallowed
  labels:
    app: nginx-readonlyrootfilesystem
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      readOnlyRootFilesystem: false

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/samples/psp-readonlyrootfilesystem/example_disallowed.yaml
```

</details>
<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-readonlyrootfilesystem-allowed
  labels:
    app: nginx-readonlyrootfilesystem
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      readOnlyRootFilesystem: true

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/samples/psp-readonlyrootfilesystem/example_allowed.yaml
```

</details>
<details>
<summary>disallowed-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-readonlyrootfilesystem-disallowed
  labels:
    app: nginx-readonlyrootfilesystem
spec:
  ephemeralContainers:
  - name: nginx
    image: nginx
    securityContext:
      readOnlyRootFilesystem: false

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/samples/psp-readonlyrootfilesystem/disallowed_ephemeral.yaml
```

</details>
<details>
<summary>exact-exemption</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-readonlyrootfilesystem-disallowed
  labels:
    app: nginx-readonlyrootfilesystem
spec:
  containers:
  - name: specialprogram
    image: specialprogram
    securityContext:
      readOnlyRootFilesystem: false

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/samples/psp-readonlyrootfilesystem/example_allowed_exempted.yaml
```

</details>


</details><details>
<summary>full-wildcard</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPReadOnlyRootFilesystem
metadata:
  name: psp-readonlyrootfilesystem
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    exemptImages:
      - "*"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/samples/full_wildcard/constraint.yaml
```

</details>

<details>
<summary>allow-normally-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-readonlyrootfilesystem-disallowed
  labels:
    app: nginx-readonlyrootfilesystem
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      readOnlyRootFilesystem: false

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/samples/psp-readonlyrootfilesystem/example_disallowed.yaml
```

</details>


</details><details>
<summary>wildcard-prefix</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPReadOnlyRootFilesystem
metadata:
  name: psp-readonlyrootfilesystem
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    exemptImages:
      - "safe-images.com/*"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/samples/wildcard-prefix/constraint.yaml
```

</details>

<details>
<summary>image-with-exempt-prefix-readOnlyRootFilesystem-not-required</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-readonlyrootfilesystem-allowed
  labels:
    app: nginx-readonlyrootfilesystem
spec:
  containers:
  - name: nginx
    image: "safe-images.com/nginx"
    securityContext:
      readOnlyRootFilesystem: false

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/samples/wildcard-prefix/example_allowed_safe_prefix.yaml
```

</details>
<details>
<summary>image-with-different-prefix-must-set-readOnlyRootFilesystem</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-readonlyrootfilesystem-allowed
  labels:
    app: nginx-readonlyrootfilesystem
spec:
  containers:
  - name: nginx
    image: "unsafe-images.com/nginx"
    securityContext:
      readOnlyRootFilesystem: false

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/read-only-root-filesystem/samples/wildcard-prefix/example_disallowed_unsafe_prefix.yaml
```

</details>


</details>