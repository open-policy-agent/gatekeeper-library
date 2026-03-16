---
id: gpuactivedeadline
title: GPU Active Deadline Required
---

# GPU Active Deadline Required

## Description
Requires pods that request NVIDIA GPU resources (nvidia.com/gpu) to set activeDeadlineSeconds. This prevents runaway training jobs from holding GPU resources indefinitely.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sgpuactivedeadline
  annotations:
    metadata.gatekeeper.sh/title: "GPU Active Deadline Required"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Requires pods that request NVIDIA GPU resources (nvidia.com/gpu) to set
      activeDeadlineSeconds. This prevents runaway training jobs from holding
      GPU resources indefinitely.
spec:
  crd:
    spec:
      names:
        kind: K8sGpuActiveDeadline
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Requires GPU pods to set activeDeadlineSeconds.
          properties:
            maxActiveDeadlineSeconds:
              description: >-
                The maximum value allowed for activeDeadlineSeconds. Set to 0 to
                only require the field is present without enforcing a maximum.
              type: integer
            exemptImages:
              description: >-
                Any container that uses an image that matches an entry in this list will be excluded
                from enforcement. Prefix-matching can be signified with `*`.
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
          - name: podRequestsGpu
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).exists(container,
                !(container.image in variables.exemptImages) &&
                has(container.resources) &&
                has(container.resources.limits) &&
                "nvidia.com/gpu" in container.resources.limits &&
                quantity(string(container.resources.limits["nvidia.com/gpu"])).compareTo(quantity("0")) > 0
              )
          - name: hasDeadline
            expression: 'has(variables.anyObject.spec.activeDeadlineSeconds)'
          - name: maxDeadline
            expression: 'has(variables.params.maxActiveDeadlineSeconds) ? variables.params.maxActiveDeadlineSeconds : 0'
          validations:
          - expression: '!variables.podRequestsGpu || variables.hasDeadline'
            messageExpression: '"Pod <" + variables.anyObject.metadata.name + "> requests GPU resources but does not set activeDeadlineSeconds"'
          - expression: '!variables.podRequestsGpu || !variables.hasDeadline || variables.maxDeadline == 0 || variables.anyObject.spec.activeDeadlineSeconds <= variables.maxDeadline'
            messageExpression: '"Pod <" + variables.anyObject.metadata.name + "> sets activeDeadlineSeconds to " + string(variables.anyObject.spec.activeDeadlineSeconds) + ", which exceeds the maximum allowed " + string(variables.maxDeadline)'
      - engine: Rego
        source:
          rego: |
            package k8sgpuactivedeadline

            violation[{"msg": msg}] {
                pod_requests_gpu
                not has_active_deadline
                msg := sprintf("Pod <%v> requests GPU resources but does not set activeDeadlineSeconds", [input.review.object.metadata.name])
            }

            violation[{"msg": msg}] {
                pod_requests_gpu
                has_active_deadline
                max_deadline := object.get(input, ["parameters", "maxActiveDeadlineSeconds"], 0)
                max_deadline > 0
                deadline := input.review.object.spec.activeDeadlineSeconds
                deadline > max_deadline
                msg := sprintf("Pod <%v> sets activeDeadlineSeconds to %v, which exceeds the maximum allowed %v", [input.review.object.metadata.name, deadline, max_deadline])
            }

            pod_requests_gpu {
                container := input_containers[_]
                not is_exempt(container)
                gpu := container.resources.limits["nvidia.com/gpu"]
                to_number(gpu) > 0
            }

            has_active_deadline {
                input.review.object.spec.activeDeadlineSeconds
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

            is_exempt(container) {
                exempt_images := object.get(input, ["parameters", "exemptImages"], [])
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuactivedeadline/template.yaml
```
## Examples
<details>
<summary>gpu-job-with-deadline</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuActiveDeadline
metadata:
  name: require-gpu-deadline
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    maxActiveDeadlineSeconds: 86400

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuactivedeadline/samples/gpu-job-with-deadline/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-job-with-deadline
spec:
  activeDeadlineSeconds: 3600
  containers:
    - name: training
      image: nvidia/cuda:12.0-runtime
      resources:
        limits:
          nvidia.com/gpu: "1"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuactivedeadline/samples/gpu-job-with-deadline/example_allowed.yaml
```

</details>


</details><details>
<summary>gpu-job-without-deadline</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuActiveDeadline
metadata:
  name: require-gpu-deadline
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuactivedeadline/samples/gpu-job-without-deadline/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-job-without-deadline
spec:
  containers:
    - name: training
      image: nvidia/cuda:12.0-runtime
      resources:
        limits:
          nvidia.com/gpu: "1"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuactivedeadline/samples/gpu-job-without-deadline/example_disallowed.yaml
```

</details>


</details><details>
<summary>non-gpu-job</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuActiveDeadline
metadata:
  name: require-gpu-deadline
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuactivedeadline/samples/non-gpu-job/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: non-gpu-job
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpuactivedeadline/samples/non-gpu-job/example_allowed.yaml
```

</details>


</details>