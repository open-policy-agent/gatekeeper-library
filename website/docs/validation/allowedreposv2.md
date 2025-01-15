---
id: allowedreposv2
title: Allowed Images
---

# Allowed Images

## Description
This policy enforces that container images must begin with a string from a specified list. The updated version, K8sAllowedReposv2, introduces support for exact match and glob-like syntax to enhance security: 1. Exact Match: By default, if the * character is not specified, the policy strictly checks for an exact match of the full registry, repository, and/or the image name. 2. Glob-like Syntax: Adding * at the end of a prefix allows prefix-based matching (e.g., registry.example.com/project/*). Only the * wildcard at the end of a string is supported. 3. Security Note: To avoid bypasses scenarios, ensure prefixes include a trailing / where appropriate (e.g., registry.example.com/project/*).

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedreposv2
  annotations:
    metadata.gatekeeper.sh/title: "Allowed Images"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      This policy enforces that container images must begin with a string from a specified list.
      The updated version, K8sAllowedReposv2, introduces support for exact match and glob-like syntax to enhance security:
      1. Exact Match: By default, if the * character is not specified, the policy strictly checks for an exact match of the full registry, repository, and/or the image name.
      2. Glob-like Syntax: Adding * at the end of a prefix allows prefix-based matching (e.g., registry.example.com/project/*). Only the * wildcard at the end of a string is supported.
      3. Security Note: To avoid bypasses scenarios, ensure prefixes include a trailing / where appropriate (e.g., registry.example.com/project/*).
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedReposv2
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            allowedImages:
              description: A list of allowed container image prefixes. Supports exact matches and prefixes ending with '*'.
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedreposv2

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not image_matches(container.image, input.parameters.allowedImages)
          msg := sprintf("container <%v> has an invalid image <%v>, allowed images are %v", [container.name, container.image, input.parameters.allowedImages])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          not image_matches(container.image, input.parameters.allowedImages)
          msg := sprintf("initContainer <%v> has an invalid image <%v>, allowed images are %v", [container.name, container.image, input.parameters.allowedImages])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.ephemeralContainers[_]
          not image_matches(container.image, input.parameters.allowedImages)
          msg := sprintf("ephemeralContainer <%v> has an invalid image <%v>, allowed images are %v", [container.name, container.image, input.parameters.allowedImages])
        }

        image_matches(image, images) {
          i_image := images[_]  # Iterate through all images in the allowed list
          not endswith(i_image, "*")  # Check for exact match if the image does not end with *
          i_image == image
        }

        image_matches(image, images) {
          i_image := images[_]  # Iterate through all images in the allowed list
          endswith(i_image, "*")  # Check for prefix match if the image ends with *
          prefix := trim_suffix(i_image, "*")
          startswith(image, prefix)
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedreposv2/template.yaml
```
## Examples
<details>
<summary>allowed-reposv2</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedReposv2
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
    allowedImages:
      - "openpolicyagent/*"
      - "myregistry.azurecr.io/*"
      - "mydockerhub/*"
      - "ubuntu:20.14"
      - "123456789123.dkr.ecr.eu-west-1.amazonaws.com/postgres"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedreposv2/samples/repo-must-be-openpolicyagent/constraint.yaml
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

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedreposv2/samples/repo-must-be-openpolicyagent/example_allowed.yaml
```

</details>
<details>
<summary>example-allowed-images</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-allowed
spec:
  containers:
    - name: image
      image: ubuntu:20.14
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedreposv2/samples/repo-must-be-openpolicyagent/example_allowed_images.yaml
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

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedreposv2/samples/repo-must-be-openpolicyagent/example_disallowed_container.yaml
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

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedreposv2/samples/repo-must-be-openpolicyagent/example_disallowed_initcontainer.yaml
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

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedreposv2/samples/repo-must-be-openpolicyagent/example_disallowed_both.yaml
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

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedreposv2/samples/repo-must-be-openpolicyagent/disallowed_all.yaml
```

</details>
<details>
<summary>disallowed-repository-and-registry</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: registry-repository-disallowed
spec:
  containers:
    - name: image-1-malicious-registry-disallow
      image: myregistry.azurecr.io.malicious.com/malicious-image
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"
    - name: image-2-registry-allow
      image: myregistry.azurecr.io/nginx
      resources:
        limits:
          cpu: "200m"
          memory: "50Mi"
    - name: image-3-malicious-image-with-registry-disallow
      image: mydockerhubmalicious/python
      resources:
        limits:
          cpu: "50m"
          memory: "10Mi"
    - name: image-4-image-with-registry-allow
      image: mydockerhub/python
      resources:
        limits:
          cpu: "50m"
          memory: "10Mi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedreposv2/samples/repo-must-be-openpolicyagent/example_disallowed_registry_and_repository.yaml
```

</details>
<details>
<summary>disallowed-repository-images</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: image-disallowed
spec:
  containers:
    - name: image-1-malicious-basic-image-disallow
      image: ubuntumalicious
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"
    - name: image-2-basic-image-allow
      image: ubuntu:20.14
      resources:
        limits:
          cpu: "200m"
          memory: "50Mi"
    - name: image-3-malicious-image-with-registry-disallow
      image: 123456789123.dkr.ecr.eu-west-1.amazonaws.com/postgresmalicious
      resources:
        limits:
          cpu: "50m"
          memory: "10Mi"
    - name: image-4-image-with-registry-allow
      image: 123456789123.dkr.ecr.eu-west-1.amazonaws.com/postgres
      resources:
        limits:
          cpu: "50m"
          memory: "10Mi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedreposv2/samples/repo-must-be-openpolicyagent/example_disallowed_images.yaml
```

</details>


</details>