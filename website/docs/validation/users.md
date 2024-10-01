---
id: users
title: Allowed Users
---

# Allowed Users

## Description
Controls the user and group IDs of the container and some volumes. Corresponds to the `runAsUser`, `runAsGroup`, `supplementalGroups`, and `fsGroup` fields in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspallowedusers
  annotations:
    metadata.gatekeeper.sh/title: "Allowed Users"
    metadata.gatekeeper.sh/version: 1.1.0
    description: >-
      Controls the user and group IDs of the container and some volumes.
      Corresponds to the `runAsUser`, `runAsGroup`, `supplementalGroups`, and
      `fsGroup` fields in a PodSecurityPolicy. For more information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups
spec:
  crd:
    spec:
      names:
        kind: K8sPSPAllowedUsers
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Controls the user and group IDs of the container and some volumes.
            Corresponds to the `runAsUser`, `runAsGroup`, `supplementalGroups`, and
            `fsGroup` fields in a PodSecurityPolicy. For more information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups
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
            runAsUser:
              type: object
              description: "Controls which user ID values are allowed in a Pod or container-level SecurityContext."
              properties:
                rule:
                  type: string
                  description: "A strategy for applying the runAsUser restriction."
                  enum:
                    - MustRunAs
                    - MustRunAsNonRoot
                    - RunAsAny
                ranges:
                  type: array
                  description: "A list of user ID ranges affected by the rule."
                  items:
                    type: object
                    description: "The range of user IDs affected by the rule."
                    properties:
                      min:
                        type: integer
                        description: "The minimum user ID in the range, inclusive."
                      max:
                        type: integer
                        description: "The maximum user ID in the range, inclusive."
            runAsGroup:
              type: object
              description: "Controls which group ID values are allowed in a Pod or container-level SecurityContext."
              properties:
                rule:
                  type: string
                  description: "A strategy for applying the runAsGroup restriction."
                  enum:
                    - MustRunAs
                    - MayRunAs
                    - RunAsAny
                ranges:
                  type: array
                  description: "A list of group ID ranges affected by the rule."
                  items:
                    type: object
                    description: "The range of group IDs affected by the rule."
                    properties:
                      min:
                        type: integer
                        description: "The minimum group ID in the range, inclusive."
                      max:
                        type: integer
                        description: "The maximum group ID in the range, inclusive."
            supplementalGroups:
              type: object
              description: "Controls the supplementalGroups values that are allowed in a Pod or container-level SecurityContext."
              properties:
                rule:
                  type: string
                  description: "A strategy for applying the supplementalGroups restriction."
                  enum:
                    - MustRunAs
                    - MayRunAs
                    - RunAsAny
                ranges:
                  type: array
                  description: "A list of group ID ranges affected by the rule."
                  items:
                    type: object
                    description: "The range of group IDs affected by the rule."
                    properties:
                      min:
                        type: integer
                        description: "The minimum group ID in the range, inclusive."
                      max:
                        type: integer
                        description: "The maximum group ID in the range, inclusive."
            fsGroup:
              type: object
              description: "Controls the fsGroup values that are allowed in a Pod or container-level SecurityContext."
              properties:
                rule:
                  type: string
                  description: "A strategy for applying the fsGroup restriction."
                  enum:
                    - MustRunAs
                    - MayRunAs
                    - RunAsAny
                ranges:
                  type: array
                  description: "A list of group ID ranges affected by the rule."
                  items:
                    type: object
                    description: "The range of group IDs affected by the rule."
                    properties:
                      min:
                        type: integer
                        description: "The minimum group ID in the range, inclusive."
                      max:
                        type: integer
                        description: "The maximum group ID in the range, inclusive."
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
                variables.exemptImagePrefixes.exists(exemption, string(container.image).startsWith(exemption))).map(container, container.image)
          - name: podRunAsUser
            expression: |
              has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.runAsUser) ? variables.anyObject.spec.securityContext.runAsUser : null
          - name: podSupplementalGroups
            expression: |
              has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.supplementalGroups) ? variables.anyObject.spec.securityContext.supplementalGroups : null
          - name: podRunAsGroup
            expression: |
              has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.runAsGroup) ? variables.anyObject.spec.securityContext.runAsGroup : null
          - name: podFsGroup
            expression: |
              has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.fsGroup) ? variables.anyObject.spec.securityContext.fsGroup : null
          - name: nonExemptContainers
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container, !(container.image in variables.exemptImages))
          - name: missingRunAsNonRootGlobal
            expression: |
              !has(variables.anyObject.securityContext) || ((!has(variables.anyObject.securityContext.runAsNonRoot) || 
              !variables.anyObject.securityContext.runAsNonRoot) && (!has(variables.anyObject.securityContext.runAsUser) || 
              variables.anyObject.securityContext.runAsUser == 0))
          - name: violatingMustOrMayRunAsUser
            expression: |
              has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) && variables.params.runAsUser.rule == "MustRunAs" ? 
                variables.nonExemptContainers.filter(container, 
                  (!has(container.securityContext) || !has(container.securityContext.runAsUser)) && variables.podRunAsUser == null
                ).map(container, "Container " + container.name + " is attempting to run without a required securityContext/runAsUser") + 
                variables.nonExemptContainers.filter(container, 
                  (has(container.securityContext) && has(container.securityContext.runAsUser) ? 
                    !variables.params.runAsUser.ranges.exists(range, 
                      container.securityContext.runAsUser >= range.min && container.securityContext.runAsUser <= range.max) : 
                    variables.podRunAsUser != null && !variables.params.runAsUser.ranges.exists(range, 
                      variables.podRunAsUser >= range.min && variables.podRunAsUser <= range.max)
                  )
                ).map(container, 
                  "Container " + container.name + " is attempting to run as disallowed user. Allowed runAsUser: {ranges: [" + 
                  variables.params.runAsUser.ranges.map(range, "{max: " + string(range.max) + ", min: " + string(range.min) + "}").join(", ") + 
                  ", rule: " + variables.params.runAsUser.rule + "}"
                ) : 
                []
          - name: violatingMustOrMayRunAsGroup
            expression: |
              has(variables.params.runAsGroup) && has(variables.params.runAsGroup.rule) && (variables.params.runAsGroup.rule == "MustRunAs" || variables.params.runAsGroup.rule == "MayRunAs") ? 
                variables.nonExemptContainers.filter(container, 
                  (!has(container.securityContext) || !has(container.securityContext.runAsGroup)) && variables.podRunAsGroup == null
                ).map(container, 
                  "Container " + container.name + " is attempting to run without a required securityContext/runAsGroup. Allowed runAsGroup: {ranges: [" + 
                  variables.params.runAsGroup.ranges.map(range, "{max: " + string(range.max) + ", min: " + string(range.min) + "}").join(", ") + ", rule: " + 
                  variables.params.runAsGroup.rule + "}"
                ) + 
                variables.nonExemptContainers.filter(container, 
                  (has(container.securityContext) && has(container.securityContext.runAsGroup)) ? 
                    !variables.params.runAsGroup.ranges.exists(range, 
                      container.securityContext.runAsGroup >= range.min && container.securityContext.runAsGroup <= range.max) : 
                    variables.podRunAsGroup != null && !variables.params.runAsGroup.ranges.exists(range, 
                      variables.podRunAsGroup >= range.min && variables.podRunAsGroup <= range.max)
                ).map(container, 
                  "Container " + container.name + " is attempting to run as disallowed group. Allowed runAsGroup: {ranges: [" + 
                  variables.params.runAsGroup.ranges.map(range, "{max: " + string(range.max) + ", min: " + string(range.min) + "}").join(", ") + 
                  ", rule: " + variables.params.runAsGroup.rule + "}"
                ) : 
                []
          - name: violatingMustOrMayRunAsFsGroup
            expression: |
              has(variables.params.fsGroup) && has(variables.params.fsGroup.rule) && (variables.params.fsGroup.rule == "MustRunAs" || variables.params.fsGroup.rule == "MayRunAs" ) ? 
                variables.nonExemptContainers.filter(container, 
                  (!has(container.securityContext) || !has(container.securityContext.fsGroup)) && variables.podFsGroup == null
                ).map(container, 
                  "Container " + container.name + " is attempting to run without a required securityContext/fsGroup. Allowed fsGroup: {ranges: [" + 
                  variables.params.fsGroup.ranges.map(range, "{max: " + string(range.max) + ", min: " + string(range.min) + "}").join(", ") + 
                  ", rule: " + variables.params.fsGroup.rule + "}"
                ) + 
                variables.nonExemptContainers.filter(container, (has(container.securityContext) && has(container.securityContext.fsGroup)) ? 
                  !variables.params.fsGroup.ranges.exists(range, 
                    container.securityContext.fsGroup >= range.min && container.securityContext.fsGroup <= range.max) : 
                  variables.podFsGroup != null && !variables.params.fsGroup.ranges.exists(range, 
                    variables.podFsGroup >= range.min && variables.podFsGroup <= range.max)
                ).map(container, "Container " + container.name + " is attempting to run as disallowed fsGroup. Allowed fsGroup: {ranges: [" + 
                  variables.params.fsGroup.ranges.map(range, "{max: " + string(range.max) + ", min: " + string(range.min) + "}").join(", ") + 
                  ", rule: " + variables.params.fsGroup.rule + "}") 
                : []
          - name: violatingMustOrMayRunAsSupplementalGroups
            expression: |
              has(variables.params.supplementalGroups) && has(variables.params.supplementalGroups.rule) && (variables.params.supplementalGroups.rule == "MustRunAs" || variables.params.supplementalGroups.rule == "MayRunAs") ? 
                variables.nonExemptContainers.filter(container, 
                  (!has(container.securityContext) || !has(container.securityContext.supplementalGroups)) && variables.podSupplementalGroups == null
                ).map(container, 
                  "Container " + container.name + " is attempting to run without a required securityContext/supplementalGroups. Allowed supplementalGroups: {ranges: [" + 
                  variables.params.supplementalGroups.ranges.map(range, "{max: " + string(range.max) + ", min: " + string(range.min) + "}").join(", ") + 
                  ", rule: " + variables.params.supplementalGroups.rule + "}"
                ) + 
                variables.nonExemptContainers.filter(container, 
                  (has(container.securityContext) && has(container.securityContext.supplementalGroups)) ? 
                    !variables.params.supplementalGroups.ranges.exists(range, 
                      container.securityContext.supplementalGroups.all(gp, gp >= range.min && gp <= range.max)) : 
                    variables.podSupplementalGroups != null && !variables.params.supplementalGroups.ranges.exists(range, 
                      variables.podSupplementalGroups.all(gp, gp >= range.min && gp <= range.max))
                ).map(container, 
                  "Container " + container.name + " is attempting to run with disallowed supplementalGroups. Allowed supplementalGroups: {ranges: [" + 
                  variables.params.supplementalGroups.ranges.map(range, "{max: " + string(range.max) + ", min: " + string(range.min) + "}").join(", ") + 
                  ", rule: " + variables.params.supplementalGroups.rule + "}") 
                : []
          - name: violatingMustRunAsNonRoot
            expression: |
              variables.nonExemptContainers.filter(container, 
                (has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) && variables.params.runAsUser.rule == "MustRunAsNonRoot") && 
                (!has(container.securityContext) || (!has(container.securityContext.runAsNonRoot) || !container.securityContext.runAsNonRoot) && 
                (!has(container.securityContext.runAsUser) || container.securityContext.runAsUser == 0)) && variables.missingRunAsNonRootGlobal
              ).map(container, 
                "Container " + container.name + " is attempting to run without a required securityContext/runAsNonRoot or securityContext/runAsUser != 0")
          - name: violations
            expression: |
              variables.violatingMustRunAsNonRoot + 
              variables.violatingMustOrMayRunAsUser + 
              variables.violatingMustOrMayRunAsGroup + 
              variables.violatingMustOrMayRunAsFsGroup + 
              variables.violatingMustOrMayRunAsSupplementalGroups
          validations:
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.violations) == 0'
            messageExpression: 'variables.violations.join(", ")'
      - engine: Rego
        source:
          rego: |
            package k8spspallowedusers

            import data.lib.exclude_update.is_update
            import data.lib.exempt_container.is_exempt

            violation[{"msg": msg}] {
              # runAsUser, runAsGroup, supplementalGroups, fsGroup fields are immutable.
              not is_update(input.review)

              fields := ["runAsUser", "runAsGroup", "supplementalGroups", "fsGroup"]
              field := fields[_]
              container := input_containers[_]
              not is_exempt(container)
              msg := get_type_violation(field, container)
            }

            get_type_violation(field, container) = msg {
              field == "runAsUser"
              params := input.parameters[field]
              msg := get_user_violation(params, container)
            }

            get_type_violation(field, container) = msg {
              field != "runAsUser"
              params := input.parameters[field]
              msg := get_violation(field, params, container)
            }

            # RunAsUser (separate due to "MustRunAsNonRoot")
            get_user_violation(params, container) = msg {
              rule := params.rule
              provided_user := get_field_value("runAsUser", container, input.review)
              not accept_users(rule, provided_user)
              msg := sprintf("Container %v is attempting to run as disallowed user %v. Allowed runAsUser: %v", [container.name, provided_user, params])
            }

            get_user_violation(params, container) = msg {
              not get_field_value("runAsUser", container, input.review)
              params.rule = "MustRunAs"
              msg := sprintf("Container %v is attempting to run without a required securityContext/runAsUser", [container.name])
            }

            get_user_violation(params, container) = msg {
              params.rule = "MustRunAsNonRoot"
              not get_field_value("runAsUser", container, input.review)
              not get_field_value("runAsNonRoot", container, input.review)
              msg := sprintf("Container %v is attempting to run without a required securityContext/runAsNonRoot or securityContext/runAsUser != 0", [container.name])
            }

            accept_users("RunAsAny", _)

            accept_users("MustRunAsNonRoot", provided_user) := provided_user != 0

            accept_users("MustRunAs", provided_user) := res  {
              ranges := input.parameters.runAsUser.ranges
              res := is_in_range(provided_user, ranges)
            }

            # Group Options
            get_violation(field, params, container) = msg {
              rule := params.rule
              provided_value := get_field_value(field, container, input.review)
              not is_array(provided_value)
              not accept_value(rule, provided_value, params.ranges)
              msg := sprintf("Container %v is attempting to run as disallowed group %v. Allowed %v: %v", [container.name, provided_value, field, params])
            }
            # SupplementalGroups is array value
            get_violation(field, params, container) = msg {
              rule := params.rule
              array_value := get_field_value(field, container, input.review)
              is_array(array_value)
              provided_value := array_value[_]
              not accept_value(rule, provided_value, params.ranges)
              msg := sprintf("Container %v is attempting to run with disallowed supplementalGroups %v. Allowed %v: %v", [container.name, array_value, field, params])
            }

            get_violation(field, params, container) = msg {
              not get_field_value(field, container, input.review)
              params.rule == "MustRunAs"
              msg := sprintf("Container %v is attempting to run without a required securityContext/%v. Allowed %v: %v", [container.name, field, field, params])
            }

            accept_value("RunAsAny", _, _)

            accept_value("MayRunAs", provided_value, ranges) := is_in_range(provided_value, ranges)

            accept_value("MustRunAs", provided_value, ranges) := is_in_range(provided_value, ranges)


            # If container level is provided, that takes precedence
            get_field_value(field, container, _) := get_seccontext_field(field, container)

            # If no container level exists, use pod level
            get_field_value(field, container, review) = out {
              not has_seccontext_field(field, container)
              pod_value := get_seccontext_field(field, review.object.spec)
              out := pod_value
            }

            # Helper Functions
            is_in_range(val, ranges) = res {
              matching := {1 | val >= ranges[j].min; val <= ranges[j].max}
              res := count(matching) > 0
            }

            has_seccontext_field(field, obj) {
              get_seccontext_field(field, obj)
            }

            has_seccontext_field(field, obj) {
              get_seccontext_field(field, obj) == false
            }

            get_seccontext_field(field, obj) = out {
              out = obj.securityContext[field]
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
          libs:
          - |
              package lib.exclude_update

              is_update(review) {
                  review.operation == "UPDATE"
              }
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/users/template.yaml
```
## Examples
<details>
<summary>users-and-groups-together</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPAllowedUsers
metadata:
  name: psp-pods-allowed-user-ranges
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    exemptImages:
    - nginx-exempt
    runAsUser:
      rule: MustRunAs # MustRunAsNonRoot # RunAsAny 
      ranges:
        - min: 100
          max: 200
    runAsGroup:
      rule: MustRunAs # MayRunAs # RunAsAny 
      ranges:
        - min: 100
          max: 200
    supplementalGroups:
      rule: MustRunAs # MayRunAs # RunAsAny 
      ranges:
        - min: 100
          max: 200
    fsGroup:
      rule: MustRunAs # MayRunAs # RunAsAny 
      ranges:
        - min: 100
          max: 200

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/users/samples/psp-pods-allowed-user-ranges/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-users-disallowed
  labels:
    app: nginx-users
spec:
  securityContext:
    supplementalGroups:
      - 250
    fsGroup: 250
  containers:
    - name: nginx
      image: nginx
      securityContext:
        runAsUser: 250
        runAsGroup: 250
  initContainers:
    - name: init-nginx
      image: nginx
      securityContext:
        runAsUser: 250
        runAsGroup: 250

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/users/samples/psp-pods-allowed-user-ranges/example_disallowed.yaml
```

</details>
<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-users-allowed
  labels:
    app: nginx-users
spec:
  securityContext:
    supplementalGroups:
      - 199
    fsGroup: 199
  containers:
    - name: nginx
      image: nginx
      securityContext:
        runAsUser: 199
        runAsGroup: 199

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/users/samples/psp-pods-allowed-user-ranges/example_allowed.yaml
```

</details>
<details>
<summary>disallowed-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-users-disallowed
  labels:
    app: nginx-users
spec:
  securityContext:
    supplementalGroups:
      - 250
    fsGroup: 250
  ephemeralContainers:
    - name: nginx
      image: nginx
      securityContext:
        runAsUser: 250
        runAsGroup: 250

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/users/samples/psp-pods-allowed-user-ranges/disallowed_ephemeral.yaml
```

</details>
<details>
<summary>example-allowed-exempt-image</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-users-allowed
  labels:
    app: nginx-users
spec:
  containers:
    - name: nginx
      image: nginx-exempt

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/users/samples/psp-pods-allowed-user-ranges/example_allowed_exempt_image.yaml
```

</details>


</details>