---
id: nounsupportedgpu
title: No Unsupported GPU Requests
---

# No Unsupported GPU Requests

## Description
Containers which request NVIDIA GPU resources (nvidia.com/gpu) must set the NVIDIA_VISIBLE_DEVICES environment variable, indicating the container image is built to consume GPUs via the NVIDIA CUDA runtime. This prevents GPU resource waste from containers that request GPUs but cannot use them.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8snounsupportedgpu
  annotations:
    metadata.gatekeeper.sh/title: "No Unsupported GPU Requests"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Containers which request NVIDIA GPU resources (nvidia.com/gpu) must set
      the NVIDIA_VISIBLE_DEVICES environment variable, indicating the container
      image is built to consume GPUs via the NVIDIA CUDA runtime. This prevents
      GPU resource waste from containers that request GPUs but cannot use them.
spec:
  crd:
    spec:
      names:
        kind: K8sNoUnsupportedGpu
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Containers which request NVIDIA GPU resources (nvidia.com/gpu) must set
            the NVIDIA_VISIBLE_DEVICES environment variable.
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
          - name: badContainers
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,
                !(container.image in variables.exemptImages) &&
                has(container.resources) &&
                has(container.resources.limits) &&
                "nvidia.com/gpu" in container.resources.limits &&
                quantity(string(container.resources.limits["nvidia.com/gpu"])).compareTo(quantity("0")) > 0 &&
                (!has(container.env) || !container.env.exists(e, e.name == "NVIDIA_VISIBLE_DEVICES"))
              ).map(container, "Container <" + container.name + "> requests nvidia.com/gpu but does not set the NVIDIA_VISIBLE_DEVICES environment variable")
          validations:
          - expression: 'size(variables.badContainers) == 0'
            messageExpression: 'variables.badContainers.join(", ")'
      - engine: Rego
        source:
          rego: |
            package k8snounsupportedgpu

            import data.lib.exempt_container.is_exempt

            violation[{"msg": msg}] {
                container := input_containers[_]
                not is_exempt(container)
                has_gpu_request(container)
                not has_nvidia_env(container)
                msg := sprintf("Container <%v> requests nvidia.com/gpu but does not set the NVIDIA_VISIBLE_DEVICES environment variable", [container.name])
            }

            has_gpu_request(container) {
                gpu := container.resources.limits["nvidia.com/gpu"]
                to_number(gpu) > 0
            }

            has_nvidia_env(container) {
                env := container.env[_]
                env.name == "NVIDIA_VISIBLE_DEVICES"
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/nounsupportedgpu/template.yaml
```
## Examples
<details>
<summary>gpu-with-env-var</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoUnsupportedGpu
metadata:
  name: require-gpu-env-var
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/nounsupportedgpu/samples/gpu-with-env-var/constraint.yaml
```

</details>

<details>
<summary>example-allowed-gpu-with-env</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-allowed
spec:
  containers:
    - name: training
      image: nvidia/cuda:12.0-runtime
      resources:
        limits:
          nvidia.com/gpu: "1"
      env:
        - name: NVIDIA_VISIBLE_DEVICES
          value: all

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/nounsupportedgpu/samples/gpu-with-env-var/example_allowed.yaml
```

</details>


</details><details>
<summary>gpu-without-env-var</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoUnsupportedGpu
metadata:
  name: require-gpu-env-var
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    exemptImages:
      - "nvidia/dcgm-exporter:*"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/nounsupportedgpu/samples/gpu-without-env-var/constraint.yaml
```

</details>

<details>
<summary>example-disallowed-gpu-no-env</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-disallowed
spec:
  containers:
    - name: training
      image: myrepo/custom-ml-image:v1
      resources:
        limits:
          nvidia.com/gpu: "1"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/nounsupportedgpu/samples/gpu-without-env-var/example_disallowed.yaml
```

</details>
<details>
<summary>example-allowed-exempt-image</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-exempt
spec:
  containers:
    - name: dcgm
      image: nvidia/dcgm-exporter:3.1.7
      resources:
        limits:
          nvidia.com/gpu: "1"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/nounsupportedgpu/samples/gpu-without-env-var/example_allowed_exempt.yaml
```

</details>


</details><details>
<summary>no-gpu-requested</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoUnsupportedGpu
metadata:
  name: require-gpu-env-var
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/nounsupportedgpu/samples/no-gpu-requested/constraint.yaml
```

</details>

<details>
<summary>example-allowed-no-gpu</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: no-gpu-pod
spec:
  containers:
    - name: web
      image: nginx:1.25
      resources:
        limits:
          cpu: "500m"
          memory: "128Mi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/nounsupportedgpu/samples/no-gpu-requested/example_allowed.yaml
```

</details>


</details>