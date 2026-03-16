---
id: requiredgpuruntimeclass
title: Required GPU Runtime Class
---

# Required GPU Runtime Class

## Description
Requires pods that request NVIDIA GPU resources (nvidia.com/gpu) to specify a runtimeClassName from an allowed list. This ensures GPU workloads use the proper container runtime (e.g., nvidia) rather than relying on default runtime hooks.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredgpuruntimeclass
  annotations:
    metadata.gatekeeper.sh/title: "Required GPU Runtime Class"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Requires pods that request NVIDIA GPU resources (nvidia.com/gpu) to specify
      a runtimeClassName from an allowed list. This ensures GPU workloads use
      the proper container runtime (e.g., nvidia) rather than relying on default
      runtime hooks.
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredGpuRuntimeClass
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Requires GPU pods to specify an allowed runtimeClassName.
          properties:
            allowedRuntimeClassNames:
              description: >-
                List of allowed runtime class names for GPU workloads (e.g., ["nvidia"]).
              type: array
              items:
                type: string
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
          - name: allowedRuntimeClassNames
            expression: 'has(variables.params.allowedRuntimeClassNames) ? variables.params.allowedRuntimeClassNames : []'
          - name: hasAllowedRc
            expression: |
              !has(variables.anyObject.spec.runtimeClassName) ? false :
                variables.anyObject.spec.runtimeClassName in variables.allowedRuntimeClassNames
          validations:
          - expression: '!variables.podRequestsGpu || size(variables.allowedRuntimeClassNames) == 0 || variables.hasAllowedRc'
            messageExpression: '"Pod <" + variables.anyObject.metadata.name + "> requests GPU resources but does not specify an allowed runtimeClassName (allowed: " + variables.allowedRuntimeClassNames.join(", ") + ")"'
      - engine: Rego
        source:
          rego: |
            package k8srequiredgpuruntimeclass

            violation[{"msg": msg}] {
                pod_requests_gpu
                allowed := object.get(input, ["parameters", "allowedRuntimeClassNames"], [])
                count(allowed) > 0
                not has_allowed_runtime_class(allowed)
                msg := sprintf("Pod <%v> requests GPU resources but does not specify an allowed runtimeClassName (allowed: %v)", [input.review.object.metadata.name, allowed])
            }

            pod_requests_gpu {
                container := input_containers[_]
                not is_exempt(container)
                gpu := container.resources.limits["nvidia.com/gpu"]
                to_number(gpu) > 0
            }

            has_allowed_runtime_class(allowed) {
                rc := input.review.object.spec.runtimeClassName
                rc == allowed[_]
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredgpuruntimeclass/template.yaml
```
## Examples
<details>
<summary>gpu-with-runtimeclass</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredGpuRuntimeClass
metadata:
  name: require-gpu-runtime
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowedRuntimeClassNames:
      - "nvidia"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredgpuruntimeclass/samples/gpu-with-runtimeclass/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-with-runtime
spec:
  runtimeClassName: nvidia
  containers:
    - name: training
      image: nvidia/cuda:12.0-runtime
      resources:
        limits:
          nvidia.com/gpu: "1"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredgpuruntimeclass/samples/gpu-with-runtimeclass/example_allowed.yaml
```

</details>


</details><details>
<summary>gpu-without-runtimeclass</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredGpuRuntimeClass
metadata:
  name: require-gpu-runtime
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowedRuntimeClassNames:
      - "nvidia"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredgpuruntimeclass/samples/gpu-without-runtimeclass/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-without-runtime
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredgpuruntimeclass/samples/gpu-without-runtimeclass/example_disallowed.yaml
```

</details>


</details><details>
<summary>no-gpu</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredGpuRuntimeClass
metadata:
  name: require-gpu-runtime
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowedRuntimeClassNames:
      - "nvidia"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredgpuruntimeclass/samples/no-gpu/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredgpuruntimeclass/samples/no-gpu/example_allowed.yaml
```

</details>


</details>