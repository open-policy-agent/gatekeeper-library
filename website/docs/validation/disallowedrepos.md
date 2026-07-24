---
id: disallowedrepos
title: Disallowed Repositories
---

# Disallowed Repositories

## Description
Disallowed container repositories that begin with a string from the specified list.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowedrepos
  annotations:
    metadata.gatekeeper.sh/title: "Disallowed Repositories"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Disallowed container repositories that begin with a string from the specified list.
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowedRepos
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            repos:
              description: The list of prefixes a container image is not allowed to have.
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdisallowedrepos

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          image := container.image
          startswith(image, input.parameters.repos[_])
          msg := sprintf("container <%v> has an invalid image repo <%v>, disallowed repos are %v", [container.name, container.image, input.parameters.repos])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          image := container.image
          startswith(image, input.parameters.repos[_])
          msg := sprintf("initContainer <%v> has an invalid image repo <%v>, disallowed repos are %v", [container.name, container.image, input.parameters.repos])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.ephemeralContainers[_]
          image := container.image
          startswith(image, input.parameters.repos[_])
          msg := sprintf("ephemeralContainer <%v> has an invalid image repo <%v>, disallowed repos are %v", [container.name, container.image, input.parameters.repos])
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedrepos/template.yaml
```
## Examples
<details>
<summary>repo-must-not-be-k8s-gcr-io</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDisallowedRepos
metadata:
  name: repo-must-not-be-k8s-gcr-io
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    repos:
      - "k8s.gcr.io/"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedrepos/samples/repo-must-not-be-k8s-gcr-io/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kustomize-allowed
spec:
  containers:
    - name: kustomize
      image: registry.k8s.io/kustomize/kustomize:v3.8.9

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedrepos/samples/repo-must-not-be-k8s-gcr-io/example_allowed.yaml
```

</details>
<details>
<summary>container-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kustomize-disallowed
spec:
  containers:
    - name: kustomize
      image: k8s.gcr.io/kustomize/kustomize:v3.8.9


```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedrepos/samples/repo-must-not-be-k8s-gcr-io/example_disallowed_container.yaml
```

</details>
<details>
<summary>initcontainer-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kustomize-disallowed
spec:
  initContainers:
  - name: kustomizeinit
    image: k8s.gcr.io/kustomize/kustomize:v3.8.9
  containers:
    - name: kustomize
      image: registry.k8s.io/kustomize/kustomize:v3.8.9

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedrepos/samples/repo-must-not-be-k8s-gcr-io/example_disallowed_initcontainer.yaml
```

</details>
<details>
<summary>both-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kustomize-disallowed
spec:
  initContainers:
  - name: kustomizeinit
    image: k8s.gcr.io/kustomize/kustomize:v3.8.9
  containers:
    - name: kustomize
      image: k8s.gcr.io/kustomize/kustomize:v3.8.9

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedrepos/samples/repo-must-not-be-k8s-gcr-io/example_disallowed_both.yaml
```

</details>
<details>
<summary>all-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kustomize-disallowed
spec:
  initContainers:
  - name: kustomize
    image:  k8s.gcr.io/kustomize/kustomize:v3.8.9
  containers:
    - name: kustomize
      image: k8s.gcr.io/kustomize/kustomize:v3.8.9
  ephemeralContainers:
    - name: kustomize
      image: k8s.gcr.io/kustomize/kustomize:v3.8.9

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedrepos/samples/repo-must-not-be-k8s-gcr-io/disallowed_all.yaml
```

</details>


</details>