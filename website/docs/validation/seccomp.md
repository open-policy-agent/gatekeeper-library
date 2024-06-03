---
id: seccomp
title: Seccomp
---

# Seccomp

## Description
Controls the seccomp profile used by containers. Corresponds to the `seccomp.security.alpha.kubernetes.io/allowedProfileNames` annotation on a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#seccomp

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspseccomp
  annotations:
    metadata.gatekeeper.sh/title: "Seccomp"
    metadata.gatekeeper.sh/version: 1.1.0
    description: >-
      Controls the seccomp profile used by containers. Corresponds to the
      `seccomp.security.alpha.kubernetes.io/allowedProfileNames` annotation on
      a PodSecurityPolicy. For more information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#seccomp
spec:
  crd:
    spec:
      names:
        kind: K8sPSPSeccomp
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Controls the seccomp profile used by containers. Corresponds to the
            `seccomp.security.alpha.kubernetes.io/allowedProfileNames` annotation on
            a PodSecurityPolicy. For more information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#seccomp
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
            allowedProfiles:
              type: array
              description: >-
                An array of allowed profile values for seccomp on Pods/Containers.

                Can use the annotation naming scheme: `runtime/default`, `docker/default`, `unconfined` and/or
                `localhost/some-profile.json`. The item `localhost/*` will allow any localhost based profile.

                Can also use the securityContext naming scheme: `RuntimeDefault`, `Unconfined`
                and/or `Localhost`. For securityContext `Localhost`, use the parameter `allowedLocalhostProfiles`
                to list the allowed profile JSON files.

                The policy code will translate between the two schemes so it is not necessary to use both.

                Putting a `*` in this array allows all Profiles to be used.

                This field is required since with an empty list this policy will block all workloads.
              items:
                type: string
            allowedLocalhostFiles:
              type: array
              description: >-
                When using securityContext naming scheme for seccomp and including `Localhost` this array holds
                the allowed profile JSON files.

                Putting a `*` in this array will allows all JSON files to be used.

                This field is required to allow `Localhost` in securityContext as with an empty list it will block.
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      code: 
      - engine: K8sNativeValidation
        source:
          variables:
          - name: namingTranslation
            expression: |
              {
                "Unconfined": "unconfined",
                "Localhost": "localhost",
                "runtime/default": "RuntimeDefault",
                "docker/default": "RuntimeDefault",
                "unconfined": "Unconfined",
                "localhost": "Localhost",
              }
          - name: containers
            expression: 'has(variables.anyObject.spec.containers) ? variables.anyObject.spec.containers : []'
          - name: initContainers
            expression: 'has(variables.anyObject.spec.initContainers) ? variables.anyObject.spec.initContainers : []'
          - name: ephemeralContainers
            expression: 'has(variables.anyObject.spec.ephemeralContainers) ? variables.anyObject.spec.ephemeralContainers : []'
          - name: allowAllProfiles
            expression: |
              has(variables.params.allowAllProfiles) && variables.params.allowAllProfiles.exists(profile, profile == "*")
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
                variables.exemptImagePrefixes.exists(exemption, string(container.image).startsWith(exemption)))
          - name: badContainers
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,
                !variables.allowAllProfiles &&
                !(container.image in variables.exemptImages))
          - name: RuntimeDefaultProfiles
            expression: |
              has(variables.params.allowedProfiles) && variables.params.allowedProfiles.exists(profile, profile == "RuntimeDefault") ? ["runtime/default", "docker/default"] : []
          - name: inputAllowedProfiles
            expression: |
              !has(variables.params.allowedProfiles) ? [] : variables.params.allowedProfiles
          - name: allowedLocalhostFiles
            expression: |
              has(variables.params.allowedLocalhostFiles) ? variables.params.allowedLocalhostFiles : []
          - name: translatedProfiles
            expression: |
              !has(variables.params.allowedProfiles) ? [] :
                (
                  (variables.params.allowedProfiles.filter(profile,
                  !profile.lowerAscii().startsWith("localhost")).map(profile, variables.namingTranslation[profile]).filter(profile, !(profile in variables.inputAllowedProfiles))) + 
                  (variables.params.allowedProfiles.exists(profile, profile == "RuntimeDefault") ? ["runtime/default", "docker/default"] : []) +
                  (variables.params.allowedProfiles.exists(profile, profile == "Localhost") ? variables.allowedLocalhostFiles.map(file, "localhost/" + file) : []) +
                  (variables.params.allowedProfiles.exists(profile, profile.startsWith("localhost")) ? ["Localhost"] : [])
                )        
          - name: allowedProfiles
            expression: |
              variables.inputAllowedProfiles + variables.translatedProfiles.filter(profile, !(profile in variables.inputAllowedProfiles))
          - name: hasPodSecurityContext
            expression: |
              has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.seccompProfile)
          - name: hasPodAnnotations
            expression: |
              has(variables.anyObject.metadata.annotations) && ("seccomp.security.alpha.kubernetes.io/pod" in variables.anyObject.metadata.annotations)
          - name: podAnnotationsProfiles
            expression: |
              variables.badContainers.filter(container, 
                !(has(container.securityContext) && has(container.securityContext.seccompProfile)) && 
                !(has(variables.anyObject.metadata.annotations) && (("container.seccomp.security.alpha.kubernetes.io/" + container.name) in variables.anyObject.metadata.annotations)) && 
                !variables.hasPodSecurityContext && 
                variables.hasPodAnnotations 
              ).map(container, {
                "container" : container.name,
                "profile" : variables.anyObject.metadata.annotations["seccomp.security.alpha.kubernetes.io/pod"],
                "file" : dyn(""),
                "location" : dyn("annotation seccomp.security.alpha.kubernetes.io/pod"),
              })
          - name: containerAnnotationsProfiles
            expression: |
              variables.badContainers.filter(container, 
                !(has(container.securityContext) && has(container.securityContext.seccompProfile)) && 
                !variables.hasPodSecurityContext && 
                has(variables.anyObject.metadata.annotations) && (("container.seccomp.security.alpha.kubernetes.io/" + container.name) in variables.anyObject.metadata.annotations)
              ).map(container, {
                "container" : container.name,
                "profile" : variables.anyObject.metadata.annotations["container.seccomp.security.alpha.kubernetes.io/" + container.name],
                "file" : dyn(""),
                "location" : dyn("annotation container.seccomp.security.alpha.kubernetes.io/" + container.name),
              })
          - name: podLocalHostProfile
            expression: |
              has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.seccompProfile) && has(variables.anyObject.spec.securityContext.seccompProfile.localhostProfile) ? variables.anyObject.spec.securityContext.seccompProfile.localhostProfile : ""
          - name: podSecurityContextProfiles
            expression: |
              variables.badContainers.filter(container, 
                !(has(container.securityContext) && has(container.securityContext.seccompProfile)) && 
                variables.hasPodSecurityContext
              ).map(container, {
                "container" : container.name,
                "profile" : variables.anyObject.spec.securityContext.seccompProfile.type,
                "file" : variables.podLocalHostProfile,
                "location" : dyn("pod securityContext"),
              })
          - name: containerSecurityContextProfiles
            expression: |
              variables.badContainers.filter(container, 
                has(container.securityContext) && has(container.securityContext.seccompProfile)
              ).map(container, {
                "container" : container.name,
                "profile" : container.securityContext.seccompProfile.type,
                "file" : has(container.securityContext.seccompProfile.localhostProfile) ? container.securityContext.seccompProfile.localhostProfile : dyn(""),
                "location" : dyn("container securityContext"),
              })
          - name: containerProfilesMissing
            expression: |
              variables.badContainers.filter(container, 
                !(has(container.securityContext) && has(container.securityContext.seccompProfile)) && 
                !(has(variables.anyObject.metadata.annotations) && (("container.seccomp.security.alpha.kubernetes.io/" + container.name) in variables.anyObject.metadata.annotations)) && 
                !variables.hasPodSecurityContext && 
                !variables.hasPodAnnotations 
              ).map(container, {
                "container" : container.name,
                "profile" : dyn("not configured"),
                "file" : dyn(""),
                "location" : dyn("no explicit profile found"),
              })
          - name: allBadContainerProfiles
            expression: |
              variables.podAnnotationsProfiles + variables.containerAnnotationsProfiles + variables.podSecurityContextProfiles + variables.containerSecurityContextProfiles + variables.containerProfilesMissing
          - name: allowAllLocalhostFiles
            expression: |
              has(variables.params.allowedLocalhostFiles) ? variables.params.allowedLocalhostFiles.exists(file, file == "*") : 
                has(variables.params.allowedProfiles) ? variables.params.allowedProfiles.exists(profile, profile == "localhost/*") : false
          - name: allowedFiles
            expression: |
              has(variables.params.allowedLocalhostFiles) ? variables.params.allowedLocalhostFiles : [] +
              variables.inputAllowedProfiles.filter(profile, profile.startsWith("localhost/")).map(profile, profile.replace("localhost/", ""))
          - name: containersWithAllowedProfiles
            expression: |
              variables.allBadContainerProfiles.filter(badContainerProfile, 
                variables.allowAllProfiles || 
                (
                  !badContainerProfile.profile.lowerAscii().startsWith("localhost") && 
                  variables.allowedProfiles.exists(allowedProfile, allowedProfile == badContainerProfile.profile)
                ) ||
                (
                  badContainerProfile.profile == "Localhost" &&
                  !variables.allowAllLocalhostFiles &&
                  variables.allowedProfiles.exists(allowedProfile, allowedProfile == badContainerProfile.profile) &&
                  variables.allowedFiles.exists(file, file == badContainerProfile.file)
                ) ||
                (
                  badContainerProfile.profile == "Localhost" &&
                  variables.allowAllLocalhostFiles &&
                  variables.allowedProfiles.exists(allowedProfile, allowedProfile == badContainerProfile.profile)
                ) || 
                (
                  variables.allowedProfiles.exists(allowedProfile, allowedProfile == "localhost/*") &&
                  badContainerProfile.profile.startsWith("localhost/")
                ) ||
                (
                  badContainerProfile.profile.startsWith("localhost/") &&
                  variables.allowedProfiles.exists(allowedProfile, allowedProfile == badContainerProfile.profile)
                ) 
              ).map(profile, profile.container)
          - name: badContainerProfilesWithoutFiles
            expression: |
              variables.allBadContainerProfiles.filter(badContainerProfile, 
                !variables.containersWithAllowedProfiles.exists(container, container == badContainerProfile.container) &&
                badContainerProfile.profile != "Localhost"
              ).map(badProfile, "Seccomp profile '" + badProfile.profile + "' is not allowed for container '" + badProfile.container + "'. Found at: " + badProfile.location + ". Allowed profiles: " + variables.allowedProfiles.join(", "))
          - name: badContainerProfilesWithFiles
            expression: |
              variables.allBadContainerProfiles.filter(badContainerProfile, 
                !variables.containersWithAllowedProfiles.exists(container, container == badContainerProfile.container) &&
                badContainerProfile.profile == "Localhost"
              ).map(badProfile, "Seccomp profile '" + badProfile.profile + "' With file '" + badProfile.file + "' is not allowed for container '" + badProfile.container + "'. Found at: " + badProfile.location + ". Allowed profiles: " + variables.allowedProfiles.join(", "))
          validations:
          - expression: 'size(variables.badContainerProfilesWithoutFiles) == 0'
            messageExpression: |
              variables.badContainerProfilesWithoutFiles.join("\n")
          - expression: 'size(variables.badContainerProfilesWithFiles) == 0'
            messageExpression: |
              variables.badContainerProfilesWithFiles.join("\n")
      rego: |
        package k8spspseccomp

        import data.lib.exempt_container.is_exempt

        container_annotation_key_prefix = "container.seccomp.security.alpha.kubernetes.io/"

        pod_annotation_key = "seccomp.security.alpha.kubernetes.io/pod"

        naming_translation = {
            # securityContext -> annotation
            "RuntimeDefault": ["runtime/default", "docker/default"],
            "Unconfined": ["unconfined"],
            "Localhost": ["localhost"],
            # annotation -> securityContext
            "runtime/default": ["RuntimeDefault"],
            "docker/default": ["RuntimeDefault"],
            "unconfined": ["Unconfined"],
            "localhost": ["Localhost"],
        }

        violation[{"msg": msg}] {
            not input_wildcard_allowed_profiles
            allowed_profiles := get_allowed_profiles
            container := input_containers[name]
            not is_exempt(container)
            result := get_profile(container)
            not allowed_profile(result.profile, result.file, allowed_profiles)
            msg := get_message(result.profile, result.file, name, result.location, allowed_profiles)
        }

        get_message(profile, _, name, location, allowed_profiles) = message {
            not profile == "Localhost"
            message := sprintf("Seccomp profile '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v", [profile, name, location, allowed_profiles])
        }

        get_message(profile, file, name, location, allowed_profiles) = message {
            profile == "Localhost"
            message := sprintf("Seccomp profile '%v' with file '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v", [profile, file, name, location, allowed_profiles])
        }

        input_wildcard_allowed_profiles {
            input.parameters.allowedProfiles[_] == "*"
        }

        input_wildcard_allowed_files {
            input.parameters.allowedLocalhostFiles[_] == "*"
        }

        input_wildcard_allowed_files {
            "localhost/*" == input.parameters.allowedProfiles[_]
        }

        # Simple allowed Profiles
        allowed_profile(profile, _, allowed) {
            not startswith(lower(profile), "localhost")
            profile == allowed[_]
        }

        # seccomp Localhost without wildcard
        allowed_profile(profile, file, allowed) {
            profile == "Localhost"
            not input_wildcard_allowed_files
            profile == allowed[_]
            allowed_files := {x | x := object.get(input.parameters, "allowedLocalhostFiles", [])[_]} | get_annotation_localhost_files
            file == allowed_files[_]
        }

        # seccomp Localhost with wildcard
        allowed_profile(profile, _, allowed) {
            profile == "Localhost"
            input_wildcard_allowed_files
            profile == allowed[_]
        }

        # annotation localhost with wildcard
        allowed_profile(profile, _, allowed) {
            "localhost/*" == allowed[_]
            startswith(profile, "localhost/")
        }

        # annotation localhost without wildcard
        allowed_profile(profile, _, allowed) {
            startswith(profile, "localhost/")
            profile == allowed[_]
        }

        # Localhost files from annotation scheme
        get_annotation_localhost_files[file] {
            profile := input.parameters.allowedProfiles[_]
            startswith(profile, "localhost/")
            file := replace(profile, "localhost/", "")
        }

        # The profiles explicitly in the list
        get_allowed_profiles[allowed] {
            allowed := input.parameters.allowedProfiles[_]
        }

        # The simply translated profiles
        get_allowed_profiles[allowed] {
            profile := input.parameters.allowedProfiles[_]
            not startswith(lower(profile), "localhost")
            allowed := naming_translation[profile][_]
        }

        # Seccomp Localhost to annotation translation
        get_allowed_profiles[allowed] {
            profile := input.parameters.allowedProfiles[_]
            profile == "Localhost"
            file := object.get(input.parameters, "allowedLocalhostFiles", [])[_]
            allowed := sprintf("%v/%v", [naming_translation[profile][_], file])
        }

        # Annotation localhost to Seccomp translation
        get_allowed_profiles[allowed] {
            profile := input.parameters.allowedProfiles[_]
            startswith(profile, "localhost")
            allowed := naming_translation.localhost[_]
        }

        # Container profile as defined in pod annotation
        get_profile(container) = {"profile": profile, "file": "", "location": location} {
            not has_securitycontext_container(container)
            not has_annotation(get_container_annotation_key(container.name))
            not has_securitycontext_pod
            profile := input.review.object.metadata.annotations[pod_annotation_key]
            location := sprintf("annotation %v", [pod_annotation_key])
        }

        # Container profile as defined in container annotation
        get_profile(container) = {"profile": profile, "file": "", "location": location} {
            not has_securitycontext_container(container)
            not has_securitycontext_pod
            container_annotation := get_container_annotation_key(container.name)
            has_annotation(container_annotation)
            profile := input.review.object.metadata.annotations[container_annotation]
            location := sprintf("annotation %v", [container_annotation])
        }

        # Container profile as defined in pods securityContext
        get_profile(container) = {"profile": profile, "file": file, "location": location} {
            not has_securitycontext_container(container)
            profile := input.review.object.spec.securityContext.seccompProfile.type
            file := object.get(input.review.object.spec.securityContext.seccompProfile, "localhostProfile", "")
            location := "pod securityContext"
        }

        # Container profile as defined in containers securityContext
        get_profile(container) = {"profile": profile, "file": file, "location": location} {
            has_securitycontext_container(container)
            profile := container.securityContext.seccompProfile.type
            file := object.get(container.securityContext.seccompProfile, "localhostProfile", "")
            location := "container securityContext"
        }

        # Container profile missing
        get_profile(container) = {"profile": "not configured", "file": "", "location": "no explicit profile found"} {
            not has_annotation(get_container_annotation_key(container.name))
            not has_annotation(pod_annotation_key)
            not has_securitycontext_pod
            not has_securitycontext_container(container)
        }

        has_annotation(annotation) {
            input.review.object.metadata.annotations[annotation]
        }

        has_securitycontext_pod {
            input.review.object.spec.securityContext.seccompProfile
        }

        has_securitycontext_container(container) {
            container.securityContext.seccompProfile
        }

        get_container_annotation_key(name) = annotation {
            annotation := concat("", [container_annotation_key_prefix, name])
        }

        input_containers[container.name] = container {
            container := input.review.object.spec.containers[_]
        }

        input_containers[container.name] = container {
            container := input.review.object.spec.initContainers[_]
        }

        input_containers[container.name] = container {
            container := input.review.object.spec.ephemeralContainers[_]
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccomp/template.yaml
```
## Examples
<details>
<summary>default-seccomp-required</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPSeccomp
metadata:
  name: psp-seccomp
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowedProfiles:
    - runtime/default
    - docker/default

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccomp/samples/psp-seccomp/constraint.yaml
```

</details>

<details>
<summary>example-disallowed-global</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-seccomp-disallowed2
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: unconfined
  labels:
    app: nginx-seccomp
spec:
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccomp/samples/psp-seccomp/example_disallowed2.yaml
```

</details>
<details>
<summary>example-disallowed-container</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-seccomp-disallowed
  annotations:
    container.seccomp.security.alpha.kubernetes.io/nginx: unconfined
  labels:
    app: nginx-seccomp
spec:
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccomp/samples/psp-seccomp/example_disallowed.yaml
```

</details>
<details>
<summary>example-allowed-container</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-seccomp-allowed
  annotations:
    container.seccomp.security.alpha.kubernetes.io/nginx: runtime/default
  labels:
    app: nginx-seccomp
spec:
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccomp/samples/psp-seccomp/example_allowed.yaml
```

</details>
<details>
<summary>example-allowed-global</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-seccomp-allowed2
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: runtime/default
  labels:
    app: nginx-seccomp
spec:
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccomp/samples/psp-seccomp/example_allowed2.yaml
```

</details>
<details>
<summary>disallowed-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-seccomp-disallowed
  annotations:
    container.seccomp.security.alpha.kubernetes.io/nginx: unconfined
  labels:
    app: nginx-seccomp
spec:
  ephemeralContainers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccomp/samples/psp-seccomp/disallowed_ephemeral.yaml
```

</details>


</details>