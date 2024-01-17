---
id: containerresources
title: Required Resources
---

# Required Resources

## Description
Requires containers to have defined resources set.
https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredresources
  annotations:
    metadata.gatekeeper.sh/title: "Required Resources"
    metadata.gatekeeper.sh/version: 1.0.1
    description: >-
      Requires containers to have defined resources set.

      https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredResources
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
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
            limits:
              type: array
              description: "A list of limits that should be enforced (`cpu`, `memory`, or both)."
              items:
                type: string
                enum:
                - cpu
                - memory
            requests:
              type: array
              description: "A list of requests that should be enforced (`cpu`, `memory`, or both)."
              items:
                type: string
                enum:
                - cpu
                - memory
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredresources

        import data.lib.exempt_container.is_exempt

        violation[{"msg": msg}] {
          general_violation[{"msg": msg, "field": "containers"}]
        }

        violation[{"msg": msg}] {
          general_violation[{"msg": msg, "field": "initContainers"}]
        }

        general_violation[{"msg": msg, "field": field}] {
          container := input.review.object.spec[field][_]
          not is_exempt(container)
          provided := {resource_type | container.resources.limits[resource_type]}
          required := {resource_type | resource_type := input.parameters.limits[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("container <%v> does not have <%v> limits defined", [container.name, missing])
        }

        general_violation[{"msg": msg, "field": field}] {
          container := input.review.object.spec[field][_]
          not is_exempt(container)
          provided := {resource_type | container.resources.requests[resource_type]}
          required := {resource_type | resource_type := input.parameters.requests[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("container <%v> does not have <%v> requests defined", [container.name, missing])
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/template.yaml
```
## Examples
<details>
<summary>container-limits-and-requests</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredResources
metadata:
  name: container-must-have-limits-and-requests
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    limits:
      - cpu
      - memory
    requests:
      - cpu
      - memory

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-limits-and-requests/constraint.yaml
```

</details>

<details>
<summary>limits-and-requests-defined-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-allowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        limits:
          cpu: "100m"
          memory: "1Gi"
        requests:
          cpu: "100m"
          memory: "1Gi"


```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-limits-and-requests/limits-and-requests-defined-allowed.yaml
```

</details>
<details>
<summary>only-requests-defined-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        requests:
          cpu: "100m"
          memory: "2Gi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-limits-and-requests/only-requests-defined-disallowed.yaml
```

</details>
<details>
<summary>only-cpu-requests-and-memory-limits-defined-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        requests:
          cpu: "100m"
        limits:
          memory: "2Gi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-limits-and-requests/only-cpu-requests-and-memory-limits-defined-disallowed.yaml
```

</details>
<details>
<summary>only-memory-limits-defined-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        limits:
          memory: "2Gi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-limits-and-requests/only-memory-limits-defined-disallowed.yaml
```

</details>


</details><details>
<summary>container-cpu-requests-memory-limits-and-requests</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredResources
metadata:
  name: container-must-have-cpu-requests-memory-limits-and-requests
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    limits:
      - memory
    requests:
      - cpu
      - memory

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-cpu-requests-memory-limits-and-requests/constraint.yaml
```

</details>

<details>
<summary>limits-and-requests-defined-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-allowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        limits:
          cpu: "100m"
          memory: "1Gi"
        requests:
          cpu: "100m"
          memory: "1Gi"


```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-cpu-requests-memory-limits-and-requests/limits-and-requests-defined-allowed.yaml
```

</details>
<details>
<summary>only-cpu-requests-and-memory-limits-and-requests-defined-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        limits:
          memory: "2Gi"
        requests:
          cpu: "100m"
          memory: "2Gi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-cpu-requests-memory-limits-and-requests/only-cpu-requests-and-memory-limits-and-requests-defined-allowed.yaml
```

</details>
<details>
<summary>only-requests-defined-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        requests:
          cpu: "100m"
          memory: "2Gi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-cpu-requests-memory-limits-and-requests/only-requests-defined-disallowed.yaml
```

</details>
<details>
<summary>only-memory-limits-defined-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        limits:
          memory: "2Gi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-cpu-requests-memory-limits-and-requests/only-memory-limits-defined-disallowed.yaml
```

</details>
<details>
<summary>empty-resources-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources: {}

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/container-must-have-cpu-requests-memory-limits-and-requests/empty-resources-disallowed.yaml
```

</details>


</details><details>
<summary>no-enforcements</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredResources
metadata:
  name: no-enforcements
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/no-enforcements/constraint.yaml
```

</details>

<details>
<summary>limits-and-requests-defined-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-allowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        limits:
          cpu: "100m"
          memory: "1Gi"
        requests:
          cpu: "100m"
          memory: "1Gi"


```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/no-enforcements/limits-and-requests-defined-allowed.yaml
```

</details>
<details>
<summary>only-requests-defined-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        requests:
          cpu: "100m"
          memory: "2Gi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/no-enforcements/only-requests-defined-allowed.yaml
```

</details>
<details>
<summary>only-cpu-requests-and-memory-limits-defined-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources:
        requests:
          cpu: "100m"
        limits:
          memory: "2Gi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/no-enforcements/only-cpu-requests-and-memory-limits-defined-allowed.yaml
```

</details>
<details>
<summary>empty-resources-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      resources: {}

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresources/samples/no-enforcements/empty-resources-allowed.yaml
```

</details>


</details>