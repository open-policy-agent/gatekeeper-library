---
id: gpuresourcelimits
title: GPU Resource Limits
---

# GPU Resource Limits

**Bundles:** `gatekeeper-gpu-safety-policies` `gatekeeper-ai-training-policies` `gatekeeper-ai-inference-policies`

## Description
Enforces a maximum number of NVIDIA GPUs (nvidia.com/gpu) that a single container may request. This prevents individual containers from hoarding GPU resources on shared clusters, particularly for AI/ML training workloads.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sgpuresourcelimits
  annotations:
    metadata.gatekeeper.sh/title: "GPU Resource Limits"
    metadata.gatekeeper.sh/version: 1.0.0
    metadata.gatekeeper.sh/bundle: "gatekeeper-gpu-safety-policies, gatekeeper-ai-training-policies, gatekeeper-ai-inference-policies"
    description: >-
      Enforces a maximum number of NVIDIA GPUs (nvidia.com/gpu) that a single
      container may request. This prevents individual containers from hoarding
      GPU resources on shared clusters, particularly for AI/ML training workloads.
spec:
  crd:
    spec:
      names:
        kind: K8sGpuResourceLimits
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Enforces a maximum number of NVIDIA GPUs per container.
          properties:
            maxGpuPerContainer:
              description: >-
                The maximum number of GPUs a single container may request.
              type: integer
            exemptImages:
              description: >-
                Any container that uses an image that matches an entry in this list will be excluded
                from enforcement. Prefix-matching can be signified with `*`. For example: `my-image-*`.
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
          - name: maxGpu
            expression: 'has(variables.params.maxGpuPerContainer) ? variables.params.maxGpuPerContainer : 0'
          - name: badContainers
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,
                !(container.image in variables.exemptImages) &&
                has(container.resources) &&
                has(container.resources.limits) &&
                "nvidia.com/gpu" in container.resources.limits &&
                quantity(string(container.resources.limits["nvidia.com/gpu"])).compareTo(quantity("0")) > 0 &&
                variables.maxGpu > 0 &&
                quantity(string(container.resources.limits["nvidia.com/gpu"])).compareTo(quantity(string(variables.maxGpu))) > 0
              ).map(container, "Container <" + container.name + "> requests " + string(container.resources.limits["nvidia.com/gpu"]) + " GPUs, which exceeds the maximum allowed " + string(variables.maxGpu))
          validations:
          - expression: 'size(variables.badContainers) == 0'
            messageExpression: 'variables.badContainers.join(", ")'
      - engine: Rego
        source:
          rego: |
            package k8sgpuresourcelimits

            import data.lib.exempt_container.is_exempt

            violation[{"msg": msg}] {
                container := input_containers[_]
                not is_exempt(container)
                gpu_count := to_number(container.resources.limits["nvidia.com/gpu"])
                gpu_count > 0
                max_gpu := object.get(input, ["parameters", "maxGpuPerContainer"], 0)
                max_gpu > 0
                gpu_count > max_gpu
                msg := sprintf("Container <%v> requests %v GPUs, which exceeds the maximum allowed %v", [container.name, gpu_count, max_gpu])
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuresourcelimits/template.yaml
```
## Examples
<details>
<summary>gpu-within-limit</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuResourceLimits
metadata:
  name: max-gpu-per-container
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    maxGpuPerContainer: 4

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuresourcelimits/samples/gpu-within-limit/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-within-limit
spec:
  containers:
    - name: training
      image: nvidia/cuda:12.0-runtime
      resources:
        limits:
          nvidia.com/gpu: "2"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuresourcelimits/samples/gpu-within-limit/example_allowed.yaml
```

</details>


</details><details>
<summary>gpu-exceeds-limit</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuResourceLimits
metadata:
  name: max-gpu-per-container
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    maxGpuPerContainer: 4

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuresourcelimits/samples/gpu-exceeds-limit/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-exceeds-limit
spec:
  containers:
    - name: training
      image: myrepo/large-training:v1
      resources:
        limits:
          nvidia.com/gpu: "8"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuresourcelimits/samples/gpu-exceeds-limit/example_disallowed.yaml
```

</details>


</details>