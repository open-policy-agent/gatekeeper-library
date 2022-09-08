---
id: allowedrepos
title: Allowed Repositories
---

# Allowed Repositories

## Description
Requires container images to begin with a string from the specified list.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedrepos
  annotations:
    metadata.gatekeeper.sh/title: "Allowed Repositories"
    description: >-
      Requires container images to begin with a string from the specified list.
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRepos
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            repos:
              description: The list of prefixes a container image is allowed to have.
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedrepos

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
          not any(satisfied)
          msg := sprintf("container <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
          not any(satisfied)
          msg := sprintf("initContainer <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.ephemeralContainers[_]
          satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
          not any(satisfied)
          msg := sprintf("ephemeralContainer <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
        }

```

## Examples
<details>
<summary>allowed-repos</summary><blockquote>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: repo-is-openpolicyagent
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - "default"
  parameters:
    repos:
      - "openpolicyagent/"

```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-allowed
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
          memory: "30Mi"

```

</details>
<details>
<summary>container-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-disallowed
spec:
  containers:
    - name: nginx
      image: nginx
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"

```

</details>
<details>
<summary>initcontainer-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-disallowed
spec:
  initContainers:
    - name: nginxinit
      image: nginx
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"
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
          memory: "30Mi"

```

</details>
<details>
<summary>both-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-disallowed
spec:
  initContainers:
  - name: nginxinit
    image: nginx
    resources:
      limits:
        cpu: "100m"
        memory: "30Mi"
  containers:
    - name: nginx
      image: nginx
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"

```

</details>
<details>
<summary>all-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-disallowed
spec:
  initContainers:
  - name: nginx
    image: nginx
    resources:
      limits:
        cpu: "100m"
        memory: "30Mi"
  containers:
    - name: nginx
      image: nginx
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"
  ephemeralContainers:
    - name: nginx
      image: nginx
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"

```

</details>


</blockquote></details>