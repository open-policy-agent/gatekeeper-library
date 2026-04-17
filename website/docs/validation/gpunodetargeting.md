---
id: gpunodetargeting
title: GPU Node Targeting
---

# GPU Node Targeting

**Bundles:** `gatekeeper-gpu-safety-policies` `gatekeeper-ai-training-policies` `gatekeeper-ai-inference-policies`

## Description
Requires pods that request NVIDIA GPU resources (nvidia.com/gpu) to target GPU-labeled nodes using required node affinity or nodeSelector. This helps ensure GPU workloads only land on nodes that advertise GPU capacity.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sgpunodetargeting
  annotations:
    metadata.gatekeeper.sh/title: "GPU Node Targeting"
    metadata.gatekeeper.sh/version: 1.0.0
    metadata.gatekeeper.sh/bundle: "gatekeeper-gpu-safety-policies, gatekeeper-ai-training-policies, gatekeeper-ai-inference-policies"
    description: >-
      Requires pods that request NVIDIA GPU resources (nvidia.com/gpu) to target
      GPU-labeled nodes using required node affinity or nodeSelector. This helps
      ensure GPU workloads only land on nodes that advertise GPU capacity.
spec:
  crd:
    spec:
      names:
        kind: K8sGpuNodeTargeting
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Requires GPU pods to target nodes with a configured GPU label key and optional values.
          properties:
            nodeLabelKey:
              description: >-
                The node label key that GPU workloads must target (for example, `nvidia.com/gpu.present`
                or `nvidia.com/gpu.product`).
              type: string
            nodeLabelValues:
              description: >-
                Optional allowed values for the GPU node label. If omitted, the policy only requires the
                label key to be present.
              type: array
              items:
                type: string
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
          - name: allContainers
            expression: 'variables.containers + variables.initContainers + variables.ephemeralContainers'
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
              variables.allContainers.filter(container,
                container.image in variables.exemptImageExplicit ||
                variables.exemptImagePrefixes.exists(exemption, string(container.image).startsWith(exemption))
              ).map(container, container.image)
          - name: podRequestsGpu
            expression: |
              variables.allContainers.exists(container,
                !(container.image in variables.exemptImages) &&
                has(container.resources) &&
                (
                  (has(container.resources.limits) &&
                    "nvidia.com/gpu" in container.resources.limits &&
                    quantity(string(container.resources.limits["nvidia.com/gpu"])).compareTo(quantity("0")) > 0) ||
                  (has(container.resources.requests) &&
                    "nvidia.com/gpu" in container.resources.requests &&
                    quantity(string(container.resources.requests["nvidia.com/gpu"])).compareTo(quantity("0")) > 0)
                )
              )
          - name: nodeLabelKey
            expression: 'has(variables.params.nodeLabelKey) ? variables.params.nodeLabelKey : ""'
          - name: nodeLabelValues
            expression: 'has(variables.params.nodeLabelValues) ? variables.params.nodeLabelValues : []'
          - name: hasMatchingNodeSelector
            expression: |
              !has(variables.anyObject.spec.nodeSelector) || !(variables.nodeLabelKey in variables.anyObject.spec.nodeSelector) ? false :
                size(variables.nodeLabelValues) == 0 || variables.anyObject.spec.nodeSelector[variables.nodeLabelKey] in variables.nodeLabelValues
          - name: hasMatchingNodeAffinity
            expression: |
              !has(variables.anyObject.spec.affinity) ||
              !has(variables.anyObject.spec.affinity.nodeAffinity) ||
              !has(variables.anyObject.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution) ||
              !has(variables.anyObject.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms) ? false :
                variables.anyObject.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms.exists(term,
                  has(term.matchExpressions) &&
                  term.matchExpressions.exists(expr,
                    expr.key == variables.nodeLabelKey &&
                    (
                      size(variables.nodeLabelValues) == 0 ?
                        expr.operator == "Exists" :
                        expr.operator == "In" &&
                        has(expr.values) &&
                        variables.nodeLabelValues.exists(value, expr.values.exists(exprValue, exprValue == value))
                    )
                  )
                )
          validations:
          - expression: '!variables.podRequestsGpu || variables.nodeLabelKey == "" || variables.hasMatchingNodeSelector || variables.hasMatchingNodeAffinity'
            messageExpression: |
              size(variables.nodeLabelValues) == 0 ?
                "Pod <" + variables.anyObject.metadata.name + "> requests GPU resources but does not target nodes with label key <" + variables.nodeLabelKey + "> using node affinity or nodeSelector" :
                "Pod <" + variables.anyObject.metadata.name + "> requests GPU resources but does not target nodes with label <" + variables.nodeLabelKey + "> matching one of <" + variables.nodeLabelValues.join(", ") + "> using node affinity or nodeSelector"
      - engine: Rego
        source:
          rego: |
            package k8sgpunodetargeting

            violation[{"msg": msg}] {
              pod_requests_gpu
              label_key := object.get(input.parameters, "nodeLabelKey", "")
              label_key != ""
              not has_matching_node_selector(label_key)
              not has_matching_node_affinity(label_key)
              label_values := object.get(input.parameters, "nodeLabelValues", [])
              msg := violation_message(label_key, label_values)
            }

            violation_message(label_key, label_values) = msg {
              count(label_values) == 0
              msg := sprintf("Pod <%v> requests GPU resources but does not target nodes with label key <%v> using node affinity or nodeSelector", [input.review.object.metadata.name, label_key])
            }

            violation_message(label_key, label_values) = msg {
              count(label_values) > 0
              msg := sprintf("Pod <%v> requests GPU resources but does not target nodes with label <%v> matching one of <%v> using node affinity or nodeSelector", [input.review.object.metadata.name, label_key, label_values])
            }

            pod_requests_gpu {
              container := all_containers[_]
              not is_exempt(container)
              requests_gpu(container)
            }

            all_containers[c] {
              c := input.review.object.spec.containers[_]
            }

            all_containers[c] {
              c := input.review.object.spec.initContainers[_]
            }

            all_containers[c] {
              c := input.review.object.spec.ephemeralContainers[_]
            }

            requests_gpu(container) {
              limits := object.get(object.get(container, "resources", {}), "limits", {})
              gpu := limits["nvidia.com/gpu"]
              to_number(gpu) > 0
            }

            requests_gpu(container) {
              requests := object.get(object.get(container, "resources", {}), "requests", {})
              gpu := requests["nvidia.com/gpu"]
              to_number(gpu) > 0
            }

            has_matching_node_selector(label_key) {
              selector := input.review.object.spec.nodeSelector
              value := selector[label_key]
              value != ""
              label_values := object.get(input.parameters, "nodeLabelValues", [])
              count(label_values) == 0
            }

            has_matching_node_selector(label_key) {
              selector := input.review.object.spec.nodeSelector
              value := selector[label_key]
              label_values := object.get(input.parameters, "nodeLabelValues", [])
              label_values[_] == value
            }

            has_matching_node_affinity(label_key) {
              term := input.review.object.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[_]
              expr := term.matchExpressions[_]
              expr.key == label_key
              label_values := object.get(input.parameters, "nodeLabelValues", [])
              count(label_values) == 0
              expr.operator == "Exists"
            }

            has_matching_node_affinity(label_key) {
              term := input.review.object.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[_]
              expr := term.matchExpressions[_]
              expr.key == label_key
              label_values := object.get(input.parameters, "nodeLabelValues", [])
              count(label_values) > 0
              expr.operator == "In"
              expr.values[_] == label_values[_]
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpunodetargeting/template.yaml
```
## Examples
<details>
<summary>gpu-pod-with-node-affinity</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuNodeTargeting
metadata:
  name: require-gpu-node-targeting
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    nodeLabelKey: "nvidia.com/gpu.present"
    nodeLabelValues:
      - "true"
```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpunodetargeting/samples/gpu-pod-with-node-affinity/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-with-node-affinity
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
          - matchExpressions:
              - key: nvidia.com/gpu.present
                operator: In
                values:
                  - "true"
  containers:
    - name: training
      image: nvidia/cuda:12.0-runtime
      resources:
        limits:
          nvidia.com/gpu: "1"
```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpunodetargeting/samples/gpu-pod-with-node-affinity/example_allowed.yaml
```

</details>


</details><details>
<summary>gpu-pod-with-node-selector</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuNodeTargeting
metadata:
  name: require-gpu-node-targeting
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    nodeLabelKey: "nvidia.com/gpu.present"
    nodeLabelValues:
      - "true"
```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpunodetargeting/samples/gpu-pod-with-node-selector/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-with-node-selector
spec:
  nodeSelector:
    nvidia.com/gpu.present: "true"
  containers:
    - name: training
      image: nvidia/cuda:12.0-runtime
      resources:
        limits:
          nvidia.com/gpu: "1"
```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpunodetargeting/samples/gpu-pod-with-node-selector/example_allowed.yaml
```

</details>


</details><details>
<summary>gpu-pod-without-targeting</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuNodeTargeting
metadata:
  name: require-gpu-node-targeting
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    nodeLabelKey: "nvidia.com/gpu.present"
    nodeLabelValues:
      - "true"
```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpunodetargeting/samples/gpu-pod-without-targeting/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-without-targeting
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpunodetargeting/samples/gpu-pod-without-targeting/example_disallowed.yaml
```

</details>


</details><details>
<summary>non-gpu-pod</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuNodeTargeting
metadata:
  name: require-gpu-node-targeting
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    nodeLabelKey: "nvidia.com/gpu.present"
    nodeLabelValues:
      - "true"
```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpunodetargeting/samples/non-gpu-pod/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: non-gpu-pod
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpunodetargeting/samples/non-gpu-pod/example_allowed.yaml
```

</details>


</details>