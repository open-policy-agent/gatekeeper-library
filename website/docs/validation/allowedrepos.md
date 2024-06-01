---
id: allowedrepos
title: Allowed Repositories
---

# Allowed Repositories

## Description
Require container images to begin with a string from a specified list of repositories or registries, or match specific image names.  The rule has been improved to allow users to distinguish between repository names, registry names, and image names, preventing bypass methods that existed in the past. For example, the rule now appends a trailing slash to repository or registry names if one is not already present. This enhancement is crucial for security, as it helps prevent attackers from bypassing controls by creating subdomains or malicious repositories that begin with the same name as those declared in the constraint file. Without the slash, a defined registry like fictional.registry.example could be exploited by an attacker setting up a malicious registry at fictional.registry.example.malicious.com. Similarly, defining a repository as "myrepo" might allow an attacker to bypass restrictions by creating a repository named "myrepoevil" on DockerHub. Additionally, this policy checks Docker image names to ensure they either match the names specified in the constraint file, end with a colon (:) for <image-name>:<tag> format, or with an at symbol (@) for <image-name>@<digest> format. This prevents attackers from using variations of valid image names to circumvent security controls.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedreposv2
  annotations:
    metadata.gatekeeper.sh/title: "Allowed Repositories"
    metadata.gatekeeper.sh/version: 2.0.0
    description: >-
      Require container images to begin with a string from a specified list of repositories or registries,
      or match specific image names. 
      The rule has been improved to allow users to distinguish between repository names, registry names, and image names,
      preventing bypass methods that existed in the past.
      For example, the rule now appends a trailing slash to repository or registry names if one is not already present.
      This enhancement is crucial for security, as it helps prevent attackers from bypassing controls by creating subdomains or
      malicious repositories that begin with the same name as those declared in the constraint file. Without the slash,
      a defined registry like fictional.registry.example could be exploited by an attacker setting up a malicious registry at
      fictional.registry.example.malicious.com. Similarly, defining a repository as "myrepo" might allow an attacker to bypass
      restrictions by creating a repository named "myrepoevil" on DockerHub.
      Additionally, this policy checks Docker image names to ensure they either match the names specified in the constraint file,
      end with a colon (:) for <image-name>:<tag> format, or with an at symbol (@) for <image-name>@<digest> format.
      This prevents attackers from using variations of valid image names to circumvent security controls.
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedReposV2
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            repos:
              description: The allowed prefixes for repositories or registries of a container image.
              type: array
              items:
                type: string
            images:
              description: The allowed prefixes for the names of container images.
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedreposv2

        # This policy checks Docker image names to ensure they either match the names specified in the constraint file
        # or end with a colon (:) for <image-name>:<tag> format
        # or with an at symbol (@) for <image-name>@<digest> format
        check_image_suffix(image_name, suffix){
          count(image_name) ==  count(suffix)
        }

        check_image_suffix(image_name,suffix){
          substring(image_name, count(suffix), 1) == ":"
        }

        check_image_suffix(image_name,suffix){
          substring(image_name, count(suffix), 1) == "@"
        }

        # This function appends a trailing slash to repository or registry names if one is not already present.
        # this enhancement is crucial for security, as it helps prevent attackers from bypassing controls by
        # creating subdomains or malicious repositories that begin with the same name as those declared in the constraint file.
        # For example, without the slash, a defined registry like fictional.registry.example could be exploited by an attacker
        # setting up a malicious registry at fictional.registry.example.malicious.com.
        # Similarly, defining a repository as "myrepo" might allow an attacker to bypass restrictions by creating a repository named "myrepoevil" on DockerHub.
        ensure_trailing_slash(repo) = result {
            not endswith(repo,"/")
            result := concat("", [repo, "/"])
        } else = repo {
            endswith(repo,"/")
        }

        # Define array of all repositories or registries with a trailing slash.
        processed_repos := [ensure_trailing_slash(repo) | repo := input.parameters.repos[_]]
        processed_images := [image | image := input.parameters.images[_]]

        # Create array for images with and without a slash.
        imagesWithSlash := [image | image := input.parameters.images[_]; contains(image, "/")]
        imagesWithoutSlash := [image | image := input.parameters.images[_]; not contains(image, "/")]

        # Concatenate user-defined repositories and registries with images to define permitted sources
        permitted_sources = array.concat(processed_repos, processed_images)

        # Check whether the given user input is a valid Docker image.
        check_image_policy(container_image)
        {
            not contains(container_image, "/")
            matching_prefixes := {prefix |
            prefix := imagesWithoutSlash[_]  # Iterate over each prefix in the list
            startswith(container_image, prefix)  # Check if the container_image starts with this prefix
            check_image_suffix(container_image,prefix)
            }

            not count(matching_prefixes) == 0
        }

        check_image_policy(container_image)
        {
            matching_prefixes := {prefix |
            prefix := imagesWithSlash[_]  # Iterate over each prefix in the list
            startswith(container_image, prefix)  # Check if the container_image starts with this prefix
            check_image_suffix(container_image,prefix)
            }
          
            not count(matching_prefixes) == 0
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not strings.any_prefix_match(container.image, processed_repos)
          not check_image_policy(container.image)
          msg := sprintf("container <%v> has an invalid image source <%v>, allowed sources are <%v>", [container.name, container.image, permitted_sources])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          not strings.any_prefix_match(container.image, processed_repos)
          not check_image_policy(container.image)
          msg := sprintf("initContainer <%v> has an invalid image source <%v>, allowed sources are <%v> ", [container.name, container.image, permitted_sources])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.ephemeralContainers[_]
          not strings.any_prefix_match(container.image, processed_repos)
          not check_image_policy(container.image)
          msg := sprintf("ephemeralContainer <%v> has an invalid source repo <%v>, allowed sources are <%v>", [container.name, container.image, permitted_sources])
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedrepos/template.yaml
```
## Examples
<details>
<summary>allowed-repos</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedReposV2
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
      - "myregistry.azurecr.io"
      - "mydockerhub"
    images:
      - "ubuntu"
      - "123456789123.dkr.ecr.eu-west-1.amazonaws.com/postgres"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedrepos/samples/repo-must-be-openpolicyagent/constraint.yaml
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedrepos/samples/repo-must-be-openpolicyagent/example_allowed.yaml
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
      image: ubuntu
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"
    - name: image_with_digest
      image: ubuntu@sha256:26c68657ccce2cb0a31b330cb0be2b5e108d467f641c62e13ab40cbec258c68d
      resources:
        limits:
          cpu: "200m"
          memory: "50Mi"
    - name: image_with_version
      image: ubuntu:20.04
      resources:
        limits:
          cpu: "200m"
          memory: "50Mi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedrepos/samples/repo-must-be-openpolicyagent/example_allowed_images.yaml
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedrepos/samples/repo-must-be-openpolicyagent/example_disallowed_container.yaml
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedrepos/samples/repo-must-be-openpolicyagent/example_disallowed_initcontainer.yaml
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedrepos/samples/repo-must-be-openpolicyagent/example_disallowed_both.yaml
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedrepos/samples/repo-must-be-openpolicyagent/disallowed_all.yaml
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedrepos/samples/repo-must-be-openpolicyagent/example_disallowed_registry_and_repository.yaml
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
      image: ubuntu:latest
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/allowedrepos/samples/repo-must-be-openpolicyagent/example_disallowed_images.yaml
```

</details>


</details>