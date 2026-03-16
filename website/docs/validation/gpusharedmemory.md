---
id: gpusharedmemory
title: GPU Shared Memory Required
---

# GPU Shared Memory Required

## Description
Requires pods that request NVIDIA GPU resources (nvidia.com/gpu) to mount a memory-backed emptyDir volume at /dev/shm. PyTorch DataLoader, NCCL multi-GPU communication, and most training frameworks require shared memory beyond the default 64MB.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sgpusharedmemory
  annotations:
    metadata.gatekeeper.sh/title: "GPU Shared Memory Required"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Requires pods that request NVIDIA GPU resources (nvidia.com/gpu) to mount a
      memory-backed emptyDir volume at /dev/shm. PyTorch DataLoader, NCCL
      multi-GPU communication, and most training frameworks require shared memory
      beyond the default 64MB.
spec:
  crd:
    spec:
      names:
        kind: K8sGpuSharedMemory
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Requires GPU pods to mount a memory-backed volume at /dev/shm.
          properties:
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
              variables.containers.filter(container,
                container.image in variables.exemptImageExplicit ||
                variables.exemptImagePrefixes.exists(exemption, string(container.image).startsWith(exemption))
              ).map(container, container.image)
          - name: volumes
            expression: 'has(variables.anyObject.spec.volumes) ? variables.anyObject.spec.volumes : []'
          - name: memoryVolNames
            expression: |
              variables.volumes.filter(v,
                has(v.emptyDir) && has(v.emptyDir.medium) && v.emptyDir.medium == "Memory"
              ).map(v, v.name)
          - name: badContainers
            expression: |
              variables.containers.filter(container,
                !(container.image in variables.exemptImages) &&
                has(container.resources) &&
                has(container.resources.limits) &&
                "nvidia.com/gpu" in container.resources.limits &&
                quantity(string(container.resources.limits["nvidia.com/gpu"])).compareTo(quantity("0")) > 0 &&
                (!has(container.volumeMounts) ||
                  !container.volumeMounts.exists(vm,
                    vm.mountPath == "/dev/shm" &&
                    vm.name in variables.memoryVolNames
                  )
                )
              ).map(container, "Container <" + container.name + "> requests GPU resources but does not mount a memory-backed volume at /dev/shm")
          validations:
          - expression: 'size(variables.badContainers) == 0'
            messageExpression: 'variables.badContainers.join(", ")'
      - engine: Rego
        source:
          rego: |
            package k8sgpusharedmemory

            violation[{"msg": msg}] {
                container := input.review.object.spec.containers[_]
                not is_exempt(container)
                has_gpu_request(container)
                not has_shm_mount(container)
                msg := sprintf("Container <%v> requests GPU resources but does not mount a memory-backed volume at /dev/shm", [container.name])
            }

            has_gpu_request(container) {
                gpu := container.resources.limits["nvidia.com/gpu"]
                to_number(gpu) > 0
            }

            has_shm_mount(container) {
                mount := container.volumeMounts[_]
                mount.mountPath == "/dev/shm"
                volume := input.review.object.spec.volumes[_]
                volume.name == mount.name
                volume.emptyDir.medium == "Memory"
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpusharedmemory/template.yaml
```
## Examples
<details>
<summary>gpu-with-shm</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuSharedMemory
metadata:
  name: require-gpu-shm
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpusharedmemory/samples/gpu-with-shm/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-with-shm
spec:
  volumes:
    - name: dshm
      emptyDir:
        medium: Memory
        sizeLimit: 8Gi
  containers:
    - name: training
      image: nvidia/cuda:12.0-runtime
      resources:
        limits:
          nvidia.com/gpu: "1"
      volumeMounts:
        - name: dshm
          mountPath: /dev/shm

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpusharedmemory/samples/gpu-with-shm/example_allowed.yaml
```

</details>


</details><details>
<summary>gpu-without-shm</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuSharedMemory
metadata:
  name: require-gpu-shm
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpusharedmemory/samples/gpu-without-shm/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod-without-shm
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpusharedmemory/samples/gpu-without-shm/example_disallowed.yaml
```

</details>


</details><details>
<summary>no-gpu</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sGpuSharedMemory
metadata:
  name: require-gpu-shm
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpusharedmemory/samples/no-gpu/constraint.yaml
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/gpusharedmemory/samples/no-gpu/example_allowed.yaml
```

</details>


</details>