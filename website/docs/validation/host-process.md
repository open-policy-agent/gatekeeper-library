---
id: host-process
title: Host Process
---

# Host Process

**Bundles:** `pod-security-baseline` `pod-security-restricted`

## Description
Disallows HostProcess containers for Windows pods. HostProcess containers enable privileged access on Windows nodes and must be disallowed in Baseline and Restricted policies. Corresponds to the windowsOptions.hostProcess field in a Pod's securityContext or container securityContext. For more information, see https://kubernetes.io/docs/concepts/security/pod-security-standards/

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spsphostprocess
  annotations:
    metadata.gatekeeper.sh/title: "Host Process"
    metadata.gatekeeper.sh/version: 1.0.1
    metadata.gatekeeper.sh/bundle: "pod-security-baseline, pod-security-restricted"
    description: >-
      Disallows HostProcess containers for Windows pods.
      HostProcess containers enable privileged access on Windows nodes
      and must be disallowed in Baseline and Restricted policies.
      Corresponds to the windowsOptions.hostProcess field in a Pod's
      securityContext or container securityContext.
      For more information, see
      https://kubernetes.io/docs/concepts/security/pod-security-standards/
spec:
  crd:
    spec:
      names:
        kind: K8sPSPHostProcess
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Disallows HostProcess containers for Windows pods.
            HostProcess containers enable privileged access on Windows nodes
            and must be disallowed in Baseline and Restricted policies.
            Corresponds to the windowsOptions.hostProcess field in a Pod's
            securityContext or container securityContext.
            For more information, see
            https://kubernetes.io/docs/concepts/security/pod-security-standards/
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
                variables.exemptImagePrefixes.exists(exemption, string(container.image).startsWith(exemption))
              ).map(container, container.image)
          - name: podHostProcess
            expression: |
              has(variables.anyObject.spec.securityContext) &&
              has(variables.anyObject.spec.securityContext.windowsOptions) &&
              has(variables.anyObject.spec.securityContext.windowsOptions.hostProcess) &&
              variables.anyObject.spec.securityContext.windowsOptions.hostProcess
          - name: badContainers
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,
                !(container.image in variables.exemptImages) &&
                has(container.securityContext) &&
                has(container.securityContext.windowsOptions) &&
                has(container.securityContext.windowsOptions.hostProcess) &&
                container.securityContext.windowsOptions.hostProcess
              ).map(container, "HostProcess container is not allowed: " + container.name + ", securityContext.windowsOptions.hostProcess: true")
          - name: isUpdate
            expression: has(request.operation) && request.operation == "UPDATE"
          validations:
          - expression: 'variables.isUpdate || !variables.podHostProcess'
            messageExpression: '"HostProcess is not allowed at pod level: " + variables.anyObject.metadata.name'
          - expression: variables.isUpdate || size(variables.badContainers) == 0
            messageExpression: 'variables.badContainers.join(", ")' 
      - engine: Rego
        source:
          rego: |
            package k8spsphostprocess

            import data.lib.exclude_update.is_update
            import data.lib.exempt_container.is_exempt

            violation[{"msg": msg, "details": {}}] {
                # spec.securityContext.windowsOptions.hostProcess field is immutable.
                not is_update(input.review)

                # Check pod-level securityContext
                input.review.object.spec.securityContext.windowsOptions.hostProcess == true
                msg := sprintf("HostProcess is not allowed at pod level: %v", [input.review.object.metadata.name])
            }

            violation[{"msg": msg, "details": {}}] {
                # spec.containers.securityContext.windowsOptions.hostProcess field is immutable.
                not is_update(input.review)

                c := input_containers[_]
                not is_exempt(c)
                c.securityContext.windowsOptions.hostProcess == true
                msg := sprintf("HostProcess container is not allowed: %v, securityContext.windowsOptions.hostProcess: true", [c.name])
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-process/template.yaml
```
## Examples
<details>
<summary>host-process-disallowed</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostProcess
metadata:
  name: psp-host-process
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-process/samples/psp-host-process/constraint.yaml
```

</details>

<details>
<summary>example-disallowed-pod-level</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-process-disallowed
  labels:
    app: nginx-host-process
spec:
  securityContext:
    windowsOptions:
      hostProcess: true
  hostNetwork: true
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-process/samples/psp-host-process/example_disallowed_pod_level.yaml
```

</details>
<details>
<summary>example-disallowed-container-level</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-process-disallowed
  labels:
    app: nginx-host-process
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      windowsOptions:
        hostProcess: true

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-process/samples/psp-host-process/example_disallowed_container_level.yaml
```

</details>
<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-process-allowed
  labels:
    app: nginx-host-process
spec:
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-process/samples/psp-host-process/example_allowed.yaml
```

</details>
<details>
<summary>disallowed-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-process-disallowed
  labels:
    app: nginx-host-process
spec:
  ephemeralContainers:
  - name: nginx
    image: nginx
    securityContext:
      windowsOptions:
        hostProcess: true

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-process/samples/psp-host-process/disallowed_ephemeral.yaml
```

</details>
<details>
<summary>disallowed-init</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-process-disallowed
  labels:
    app: nginx-host-process
spec:
  containers:
  - name: nginx
    image: nginx
  initContainers:
  - name: nginx-init
    image: nginx
    securityContext:
      windowsOptions:
        hostProcess: true

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-process/samples/psp-host-process/disallowed_init.yaml
```

</details>


</details>