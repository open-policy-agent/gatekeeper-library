---
id: seccompv2
title: Seccomp V2
---

# Seccomp V2

## Description
Controls the seccomp profile used by containers. Corresponds to the `seccomp.security.alpha.kubernetes.io/allowedProfileNames` annotation on a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#seccompv2

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspseccompv2
  annotations:
    metadata.gatekeeper.sh/title: "Seccomp V2"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Controls the seccomp profile used by containers. Corresponds to the
      `seccomp.security.alpha.kubernetes.io/allowedProfileNames` annotation on
      a PodSecurityPolicy. For more information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#seccompv2
spec:
  crd:
    spec:
      names:
        kind: K8sPSPSeccompV2
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Controls the seccomp profile used by containers. Corresponds to the
            `seccomp.security.alpha.kubernetes.io/allowedProfileNames` annotation on
            a PodSecurityPolicy. For more information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#seccompv2
          properties:
            allowAnnotations:
              description: >-
                Allow reading security contexts from annotations. If set to true, the policy will read security contexts from annotations when missing in spec.
              type: boolean
              default: true
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
              }
          - name: containers
            expression: 'has(variables.anyObject.spec.containers) ? variables.anyObject.spec.containers : []'
          - name: initContainers
            expression: 'has(variables.anyObject.spec.initContainers) ? variables.anyObject.spec.initContainers : []'
          - name: ephemeralContainers
            expression: 'has(variables.anyObject.spec.ephemeralContainers) ? variables.anyObject.spec.ephemeralContainers : []'
          - name: allowAllProfiles
            expression: |
              has(variables.params.allowedProfiles) && variables.params.allowedProfiles.exists(profile, profile == "*")
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
          - name: unverifiedContainers
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,
                !variables.allowAllProfiles &&
                !(container.image in variables.exemptImages))
          - name: inputAllowedProfiles
            expression: |
              !has(variables.params.allowedProfiles) ? [] : variables.params.allowedProfiles
          - name: allowedLocalhostFiles
            expression: |
              has(variables.params.allowedLocalhostFiles) ? variables.params.allowedLocalhostFiles : []
          - name: allowedProfilesTranslation
            expression: |
              (variables.inputAllowedProfiles.filter(profile,
              profile != "Localhost").map(profile, (profile in variables.namingTranslation) ? variables.namingTranslation[profile] : profile)) + 
              (variables.inputAllowedProfiles.exists(profile, profile == "RuntimeDefault") ? ["runtime/default", "docker/default"] : [])
          - name: allowSecurityContextLocalhost
            expression: |
              variables.inputAllowedProfiles.exists(profile, profile == "Localhost")
          - name: derivedAllowedLocalhostFiles
            expression: |
              variables.allowSecurityContextLocalhost ? variables.params.allowedLocalhostFiles.map(file, "localhost/" + file) : []
          - name: localhostWildcardAllowed
            expression: |
              variables.inputAllowedProfiles.exists(profile, profile == "localhost/*") || variables.derivedAllowedLocalhostFiles.exists(profile, profile == "localhost/*")
          - name: allowedProfiles
            expression: |
              (variables.allowedProfilesTranslation + variables.derivedAllowedLocalhostFiles).filter(entry, entry != "localhost/*")
          - name: hasPodSeccomp
            expression: |
              has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.seccompProfile)
          - name: hasPodAnnotations
            expression: |
              has(variables.anyObject.metadata.annotations) && ("seccomp.security.alpha.kubernetes.io/pod" in variables.anyObject.metadata.annotations)
          - name: podAnnotationsProfiles
            expression: |
              variables.unverifiedContainers.filter(container, 
                variables.params.allowAnnotations &&
                !(has(container.securityContext) && has(container.securityContext.seccompProfile)) && 
                !(has(variables.anyObject.metadata.annotations) && (("container.seccomp.security.alpha.kubernetes.io/" + container.name) in variables.anyObject.metadata.annotations)) && 
                !variables.hasPodSeccomp && 
                variables.hasPodAnnotations 
              ).map(container, {
                "container" : container.name,
                "profile" : variables.anyObject.metadata.annotations["seccomp.security.alpha.kubernetes.io/pod"],
                "file" : dyn(""),
                "location" : dyn("annotation seccomp.security.alpha.kubernetes.io/pod"),
              })
          - name: containerAnnotationsProfiles
            expression: |
              variables.unverifiedContainers.filter(container, 
                variables.params.allowAnnotations &&
                !(has(container.securityContext) && has(container.securityContext.seccompProfile)) && 
                !variables.hasPodSeccomp && 
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
          - name: canonicalPodSecurityContextProfile
            expression: |
              has(variables.hasPodSeccomp) && has(variables.anyObject.spec.securityContext.seccompProfile.type) ? 
                (variables.anyObject.spec.securityContext.seccompProfile.type == "RuntimeDefault" ? "runtime/default" : 
                variables.anyObject.spec.securityContext.seccompProfile.type == "Unconfined" ? "unconfined" : variables.anyObject.spec.securityContext.seccompProfile.type == "Localhost" ? "localhost/" + variables.anyObject.spec.securityContext.seccompProfile.localhostProfile : "")
                : ""
          - name: podSecurityContextProfiles
            expression: |
              variables.unverifiedContainers.filter(container, 
                !(has(container.securityContext) && has(container.securityContext.seccompProfile)) && 
                variables.hasPodSeccomp
              ).map(container, {
                "container" : container.name,
                "profile" : dyn(variables.canonicalPodSecurityContextProfile),
                "file" : variables.podLocalHostProfile,
                "location" : dyn("pod securityContext"),
              })
          - name: containerSecurityContextProfiles
            expression: |
              variables.unverifiedContainers.filter(container, 
                has(container.securityContext) && has(container.securityContext.seccompProfile)
              ).map(container, {
                "container" : container.name,
                "profile" : dyn(has(container.securityContext.seccompProfile.type) ? (container.securityContext.seccompProfile.type == "RuntimeDefault" ? "runtime/default" : 
                container.securityContext.seccompProfile.type == "Unconfined" ? "unconfined" : container.securityContext.seccompProfile.type == "Loclhost" ? "localhost/" + container.securityContext.seccompProfile.localhostProfile : "")
                : ""),
                "file" : has(container.securityContext.seccompProfile.localhostProfile) ? container.securityContext.seccompProfile.localhostProfile : dyn(""),
                "location" : dyn("container securityContext"),
              })
          - name: containerProfilesMissing
            expression: |
              variables.unverifiedContainers.filter(container, 
                !(has(container.securityContext) && has(container.securityContext.seccompProfile)) && 
                !variables.hasPodSeccomp && 
                (!(variables.params.allowAnnotations) ||
                !(has(variables.anyObject.metadata.annotations) && (("container.seccomp.security.alpha.kubernetes.io/" + container.name) in variables.anyObject.metadata.annotations)) && 
                !variables.hasPodAnnotations)
              ).map(container, {
                "container" : container.name,
                "profile" : dyn("not configured"),
                "file" : dyn(""),
                "location" : dyn("no explicit profile found"),
              })
          - name: allContainerProfiles
            expression: |
              variables.podAnnotationsProfiles + variables.containerAnnotationsProfiles + variables.podSecurityContextProfiles + variables.containerSecurityContextProfiles + variables.containerProfilesMissing
          - name: badContainerProfilesWithoutFiles
            expression: |
              variables.allContainerProfiles.filter(badContainerProfile, 
                  !badContainerProfile.profile.startsWith("localhost/") &&
                  !(badContainerProfile.profile in variables.allowedProfiles)
              ).map(badProfile, "Seccomp profile '" + badProfile.profile + "' is not allowed for container '" + badProfile.container + "'. Found at: " + badProfile.location + ". Allowed profiles: " + variables.allowedProfiles.join(", "))
          - name: badContainerProfilesWithFiles
            expression: |
              variables.allContainerProfiles.filter(badContainerProfile, 
                badContainerProfile.profile.startsWith("localhost/") &&
                !variables.localhostWildcardAllowed &&
                !(badContainerProfile.profile in variables.allowedProfiles)
              ).map(badProfile, "Seccomp profile '" + badProfile.profile + "' With file '" + badProfile.file + "' is not allowed for container '" + badProfile.container + "'. Found at: " + badProfile.location + ". Allowed profiles: " + variables.allowedProfiles.join(", "))
          validations:
          - expression: 'size(variables.badContainerProfilesWithoutFiles) == 0'
            messageExpression: |
              variables.badContainerProfilesWithoutFiles.join("\n")
          - expression: 'size(variables.badContainerProfilesWithFiles) == 0'
            messageExpression: |
              variables.badContainerProfilesWithFiles.join("\n")
      - engine: Rego
        source:
          rego: |
            package k8spspseccomp

            import data.lib.exempt_container.is_exempt

            container_annotation_key_prefix = "container.seccomp.security.alpha.kubernetes.io/"

            pod_annotation_key = "seccomp.security.alpha.kubernetes.io/pod"

            naming_translation = {
                "RuntimeDefault": ["runtime/default", "docker/default"],
                "Unconfined": ["unconfined"],
                "Localhost": ["localhost"],
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
                profile != "Localhost"
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
                not startswith(profile, "localhost/")
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

            # The profiles explicitly in the list
            get_allowed_profiles[allowed] {
                allowed := input.parameters.allowedProfiles[_]
            }

            # The simply translated profiles
            get_allowed_profiles[allowed] {
                profile := input.parameters.allowedProfiles[_]
                profile != "Localhost"
                allowed := naming_translation[profile][_]
            }

            # Seccomp Localhost to annotation translation
            get_allowed_profiles[allowed] {
                profile := input.parameters.allowedProfiles[_]
                profile == "Localhost"
                file := object.get(input.parameters, "allowedLocalhostFiles", [])[_]
                allowed := sprintf("%v/%v", [naming_translation[profile][_], file])
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
                profile := canonicalize_seccomp_profile(input.review.object.spec.securityContext.seccompProfile)
                file := object.get(input.review.object.spec.securityContext.seccompProfile, "localhostProfile", "")
                location := "pod securityContext"
            }

            # Container profile as defined in containers securityContext
            get_profile(container) = {"profile": profile, "file": file, "location": location} {
                has_securitycontext_container(container)
                profile := canonicalize_seccomp_profile(container.securityContext.seccompProfile)
                file := object.get(container.securityContext.seccompProfile, "localhostProfile", "")
                location := "container securityContext"
            }

            # Container profile missing
            get_profile(container) = {"profile": "not configured", "file": "", "location": "no explicit profile found"} {
                not has_securitycontext_container(container)
                not has_securitycontext_pod
                allow_annotations(container.name)
            }

            allow_annotations(name) {
                input.parameters.allowAnnotations
                not has_annotation(get_container_annotation_key(name))
                not has_annotation(pod_annotation_key)
            }

            allow_annotations(name) {
                not input.parameters.allowAnnotations
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

            canonicalize_seccomp_profile(profile) = out {
                profile.type == "RuntimeDefault"
                out := "runtime/default"
            }

            canonicalize_seccomp_profile(profile) = out {
                profile.type == "Unconfined"
                out := "unconfined"
            }

            canonicalize_seccomp_profile(profile) = out {
                profile.type = "Localhost"
                out := sprintf("localhost/%s", [profile.localhostProfile])
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/template.yaml
```
## Examples
<details>
<summary>default-seccomp-required</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPSeccompV2
metadata:
  name: psp-seccomp
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowAnnotations: false
    allowedProfiles:
    - runtime/default
    - docker/default

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/constraint.yaml
```

</details>

<details>
<summary>example-disallowed-global</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-seccomp-disallowed2
  labels:
    app: nginx-seccomp
spec:
  securityContext:
    seccompProfile:
      type: Unconfined
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/example_disallowed2.yaml
```

</details>
<details>
<summary>example-disallowed-container</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-seccomp-disallowed
  labels:
    app: nginx-seccomp
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      seccompProfile:
        type: Unconfined

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/example_disallowed.yaml
```

</details>
<details>
<summary>example-allowed-container</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-seccomp-allowed
  labels:
    app: nginx-seccomp
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      seccompProfile:
        type: RuntimeDefault

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/example_allowed.yaml
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
    seccomp.security.alpha.kubernetes.io/pod: runtime/default
  labels:
    app: nginx-seccomp
spec:
  ephemeralContainers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/disallowed_ephemeral.yaml
```

</details>


</details>