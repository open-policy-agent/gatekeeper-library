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
                variables.exemptImagePrefixes.exists(exemption, string(container.image).startsWith(exemption)))
          - name: podRunAsUser
            expression: |
              variables.anyObject.kind == "Pod" && has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.runAsUser) ? variables.anyObject.spec.securityContext.runAsUser : null
          - name: podRunAsSupplementalGroups
            expression: |
              variables.anyObject.kind == "Pod" && has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.supplementalGroups) ? variables.anyObject.spec.securityContext.supplementalGroups : null
          - name: podRunAsGroup
            expression: |
              variables.anyObject.kind == "Pod" && has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.runAsGroup) ? variables.anyObject.spec.securityContext.runAsGroup : null
          - name: podRunAsFsGroup
            expression: |
              variables.anyObject.kind == "Pod" && has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.fsGroup) ? variables.anyObject.spec.securityContext.fsGroup : null
          - name: missingRunAsNonRootGlobal
            expression: |
              !has(variables.anyObject.securityContext) || ((!has(variables.anyObject.securityContext.runAsNonRoot) || !variables.anyObject.securityContext.runAsNonRoot) && (!has(variables.anyObject.securityContext.runAsUser) || variables.anyObject.securityContext.runAsUser == 0))
          - name: missingRequiredRunAsUserContainers
            expression: |
              variables.containers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) && (variables.params.runAsUser.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.runAsUser)) || 
                  (variables.podRunAsUser != null)))
          - name: missingRequiredRunAsNonRootContainers
            expression: |
              variables.containers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) && (variables.params.runAsUser.rule == "MustRunAsNonRoot") ?
                (
                  (!has(container.securityContext) || (
                    (!has(container.securityContext.runAsNonRoot) || !container.securityContext.runAsNonRoot) && (!has(container.securityContext.runAsUser) || container.securityContext.runAsUser == 0) 
                  )) || variables.missingRunAsNonRootGlobal
                ) : false
              )
          - name: processedRunAsUserContainers
            expression: (variables.missingRequiredRunAsNonRootContainers + variables.missingRequiredRunAsUserContainers).map(container, container.name)
          - name: invalidRunAsUserContainers
            expression: |
              variables.containers.filter(container, 
                !(container.image in variables.exemptImages) &&
                !(container.name in variables.processedRunAsUserContainers) &&
                has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) ? 
                (
                  variables.params.runAsUser.rule == "RunAsAny" ? false :
                  (
                    variables.params.runAsUser.rule == "MustRunAsNonRoot" ?
                    (
                      has(container.securityContext) && has(container.securityContext.runAsUser) ? (container.securityContext.runAsUser == 0) : 
                        (variables.podRunAsUser == null) || variables.podRunAsUser == 0
                    ) :
                    (
                      variables.params.runAsUser.rule == "MustRunAs" ?
                      (
                        has(container.securityContext) && has(container.securityContext.runAsUser) ? !variables.params.runAsUser.ranges.exists(range, container.securityContext.runAsUser >= range.min && container.securityContext.runAsUser <= range.max) :
                          variables.podRunAsUser == null || !variables.params.runAsUser.ranges.exists(range, variables.podRunAsUser >= range.min && variables.podRunAsUser <= range.max)
                      ) : false
                    )
                  )
                ) : false
              )
          - name: missingRequiredRunAsGroupContainers
            expression: |
              variables.containers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.runAsGroup) && has(variables.params.runAsGroup.rule) && (variables.params.runAsGroup.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.runAsGroup)) || 
                  (variables.podRunAsGroup != null))
              )
          - name: invalidRunAsGroupContainers
            expression: |
              variables.containers.filter(container, 
                !(container.image in variables.exemptImages) && 
                !(variables.missingRequiredRunAsGroupContainers.exists(c, c.name == container.name)) &&
                (
                  has(variables.params.runAsGroup) && has(variables.params.runAsGroup.rule) ? 
                  (
                    variables.params.runAsGroup.rule == "RunAsAny" ? false :
                    (
                      (variables.params.runAsGroup.rule == "MustRunAs" || variables.params.runAsGroup.rule == "MayRunAs") && 
                      (
                        has(container.securityContext) && has(container.securityContext.runAsGroup) ? 
                          !variables.params.runAsGroup.ranges.exists(range, container.securityContext.runAsGroup >= range.min && container.securityContext.runAsGroup <= range.max) : 
                          variables.podRunAsGroup == null || !variables.params.runAsGroup.ranges.exists(range, variables.podRunAsGroup >= range.min && variables.podRunAsGroup <= range.max)
                      )
                    )
                  )
                  : false
                )
              )
          - name: missingRequiredFsGroupContainers
            expression: |
              variables.containers.filter(container, 
                has(variables.params.fsGroup) && has(variables.params.fsGroup.rule) && (variables.params.fsGroup.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.fsGroup)) || 
                  (variables.podRunAsFsGroup != null))
              )
          - name: invalidRunAsFsGroupContainers
            expression: |
              variables.containers.filter(container, 
                !(container.image in variables.exemptImages) &&
                !(variables.missingRequiredFsGroupContainers.exists(c, c.name == container.name)) &&
                (
                  has(variables.params.fsGroup) && has(variables.params.fsGroup.rule) ? 
                  (
                    variables.params.fsGroup.rule == "RunAsAny" ? false :
                    (
                      (variables.params.fsGroup.rule == "MustRunAs" || variables.params.fsGroup.rule == "MayRunAs") && 
                      (
                        has(container.securityContext) && has(container.securityContext.fsGroup) ? 
                          !variables.params.fsGroup.ranges.exists(range, container.securityContext.fsGroup >= range.min && container.securityContext.fsGroup <= range.max) : 
                          variables.podRunAsFsGroup == null || !variables.params.fsGroup.ranges.exists(range, variables.podRunAsFsGroup >= range.min && variables.podRunAsFsGroup <= range.max)
                      )
                    )
                  )
                  : false
                )
              )
          - name: missingRequiredSupplementalGroupsContainers
            expression: |
              variables.containers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.supplementalGroups) && has(variables.params.supplementalGroups.rule) && (variables.params.supplementalGroups.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.supplementalGroups)) || 
                  (variables.podRunAsSupplementalGroups != null)))
          - name: invalidSupplimentalGroupsContainers
            expression: |
              variables.containers.filter(container, 
                !(container.image in variables.exemptImages) &&
                !(variables.missingRequiredSupplementalGroupsContainers.exists(c, c.name == container.name)) &&
                (
                  has(variables.params.supplementalGroups) && has(variables.params.supplementalGroups.rule) ? 
                  (
                    variables.params.supplementalGroups.rule == "RunAsAny" ? false :
                    (
                      (variables.params.supplementalGroups.rule == "MustRunAs" || variables.params.supplementalGroups.rule == "MayRunAs") && 
                      (
                        has(container.securityContext) && has(container.securityContext.supplementalGroups) ? 
                          !variables.params.supplementalGroups.ranges.exists(range, container.securityContext.supplementalGroups.all(gp, gp>= range.min && gp <= range.max)) : 
                          variables.podRunAsSupplementalGroups == null || !variables.params.supplementalGroups.ranges.exists(range, variables.podRunAsSupplementalGroups.all(gp, gp >= range.min && gp <= range.max))
                      )
                    )
                  )
                  : false
                )
              )
          - name: missingRequiredRunAsUserInitContainers
            expression: |
              variables.initContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) && (variables.params.runAsUser.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.runAsUser)) || 
                  (variables.podRunAsUser != null)))
          - name: missingRequiredRunAsNonRootInitContainers
            expression: |
              variables.initContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) && (variables.params.runAsUser.rule == "MustRunAsNonRoot") ?
                (
                  has(container.securityContext) ? (
                    (!has(container.securityContext.runAsNonRoot) || !container.securityContext.runAsNonRoot) && (!has(container.securityContext.runAsUser) || container.securityContext.runAsUser == 0) && variables.missingRunAsNonRootGlobal
                  ) : variables.missingRunAsNonRootGlobal
                ) : false
              )
          - name: processedRunAsUserInitContainers
            expression: (variables.missingRequiredRunAsNonRootInitContainers + variables.missingRequiredRunAsUserInitContainers).map(container, container.name)
          - name: invalidRunAsUserInitContainers
            expression: |
              variables.initContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                !(container.name in variables.processedRunAsUserInitContainers) &&
                has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) ? 
                (
                  variables.params.runAsUser.rule == "RunAsAny" ? false :
                  (
                    variables.params.runAsUser.rule == "MustRunAsNonRoot" ?
                    (
                      has(container.securityContext) && has(container.securityContext.runAsUser) ? (container.securityContext.runAsUser == 0) : 
                        (variables.podRunAsUser == null) || variables.podRunAsUser == 0
                    ) :
                    (
                      variables.params.runAsUser.rule == "MustRunAs" ?
                      (
                        has(container.securityContext) && has(container.securityContext.runAsUser) ? !variables.params.runAsUser.ranges.exists(range, container.securityContext.runAsUser >= range.min && container.securityContext.runAsUser <= range.max) :
                          variables.podRunAsUser == null || !variables.params.runAsUser.ranges.exists(range, variables.podRunAsUser >= range.min && variables.podRunAsUser <= range.max)
                      ) : false
                    )
                  )
                ) : false
              )
          - name: missingRequiredRunAsGroupInitContainers
            expression: |
              variables.initContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.runAsGroup) && has(variables.params.runAsGroup.rule) && (variables.params.runAsGroup.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.runAsGroup)) || 
                  (variables.podRunAsGroup != null))
              )
          - name: invalidRunAsGroupInitContainers
            expression: |
              variables.initContainers.filter(container, 
                !(container.image in variables.exemptImages) && 
                !(variables.missingRequiredRunAsGroupInitContainers.exists(c, c.name == container.name)) &&
                (
                  has(variables.params.runAsGroup) && has(variables.params.runAsGroup.rule) ? 
                  (
                    variables.params.runAsGroup.rule == "RunAsAny" ? false :
                    (
                      (variables.params.runAsGroup.rule == "MustRunAs" || variables.params.runAsGroup.rule == "MayRunAs") && 
                      (
                        has(container.securityContext) && has(container.securityContext.runAsGroup) ? 
                          !variables.params.runAsGroup.ranges.exists(range, container.securityContext.runAsGroup >= range.min && container.securityContext.runAsGroup <= range.max) : 
                          variables.podRunAsGroup == null || !variables.params.runAsGroup.ranges.exists(range, variables.podRunAsGroup >= range.min && variables.podRunAsGroup <= range.max)
                      )
                    )
                  )
                  : false
                )
              )
          - name: missingRequiredFsGroupInitContainers
            expression: |
              variables.initContainers.filter(container, 
                has(variables.params.fsGroup) && has(variables.params.fsGroup.rule) && (variables.params.fsGroup.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.fsGroup)) || 
                  (variables.podRunAsFsGroup != null))
              )
          - name: invalidRunAsFsGroupInitContainers
            expression: |
              variables.initContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                !(variables.missingRequiredFsGroupInitContainers.exists(c, c.name == container.name)) &&
                (
                  has(variables.params.fsGroup) && has(variables.params.fsGroup.rule) ? 
                  (
                    variables.params.fsGroup.rule == "RunAsAny" ? false :
                    (
                      (variables.params.fsGroup.rule == "MustRunAs" || variables.params.fsGroup.rule == "MayRunAs") && 
                      (
                        has(container.securityContext) && has(container.securityContext.fsGroup) ? 
                          !variables.params.fsGroup.ranges.exists(range, container.securityContext.fsGroup >= range.min && container.securityContext.fsGroup <= range.max) : 
                          variables.podRunAsFsGroup == null || !variables.params.fsGroup.ranges.exists(range, variables.podRunAsFsGroup >= range.min && variables.podRunAsFsGroup <= range.max)
                      )
                    )
                  )
                  : false
                )
              )
          - name: missingRequiredSupplementalGroupsInitContainers
            expression: |
              variables.initContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.supplementalGroups) && has(variables.params.supplementalGroups.rule) && (variables.params.supplementalGroups.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.supplementalGroups)) || 
                  (variables.podRunAsSupplementalGroups != null)))
          - name: invalidSupplimentalGroupsInitContainers
            expression: |
              variables.initContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                !(variables.missingRequiredSupplementalGroupsInitContainers.exists(c, c.name == container.name)) &&
                (
                  has(variables.params.supplementalGroups) && has(variables.params.supplementalGroups.rule) ? 
                  (
                    variables.params.supplementalGroups.rule == "RunAsAny" ? false :
                    (
                      (variables.params.supplementalGroups.rule == "MustRunAs" || variables.params.supplementalGroups.rule == "MayRunAs") && 
                      (
                        has(container.securityContext) && has(container.securityContext.supplementalGroups) ? 
                          !variables.params.supplementalGroups.ranges.exists(range, container.securityContext.supplementalGroups.all(gp, gp>= range.min && gp <= range.max)) : 
                          variables.podRunAsSupplementalGroups == null || !variables.params.supplementalGroups.ranges.exists(range, variables.podRunAsSupplementalGroups.all(gp, gp >= range.min && gp <= range.max))
                      )
                    )
                  )
                  : false
                )
              )
          - name: missingRequiredRunAsUserEphemeralContainers
            expression: |
              variables.ephemeralContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) && (variables.params.runAsUser.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.runAsUser)) || 
                  (variables.podRunAsUser != null)))
          - name: missingRequiredRunAsNonRootEphemeralContainers
            expression: |
              variables.ephemeralContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) && (variables.params.runAsUser.rule == "MustRunAsNonRoot") ?
                (
                  has(container.securityContext) ? (
                    (!has(container.securityContext.runAsNonRoot) || !container.securityContext.runAsNonRoot) && (!has(container.securityContext.runAsUser) || container.securityContext.runAsUser == 0) && variables.missingRunAsNonRootGlobal
                  ) : variables.missingRunAsNonRootGlobal
                ) : false
              )
          - name: processedRunAsUserEphemeralContainers
            expression: (variables.missingRequiredRunAsNonRootEphemeralContainers + variables.missingRequiredRunAsUserEphemeralContainers).map(container, container.name)
          - name: invalidRunAsUserEphemeralContainers
            expression: |
              variables.ephemeralContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                !(container.name in variables.processedRunAsUserEphemeralContainers) &&
                has(variables.params.runAsUser) && has(variables.params.runAsUser.rule) ? 
                (
                  variables.params.runAsUser.rule == "RunAsAny" ? false :
                  (
                    variables.params.runAsUser.rule == "MustRunAsNonRoot" ?
                    (
                      has(container.securityContext) && has(container.securityContext.runAsUser) ? (container.securityContext.runAsUser == 0) : 
                        (variables.podRunAsUser == null) || variables.podRunAsUser == 0
                    ) :
                    (
                      variables.params.runAsUser.rule == "MustRunAs" ?
                      (
                        has(container.securityContext) && has(container.securityContext.runAsUser) ? !variables.params.runAsUser.ranges.exists(range, container.securityContext.runAsUser >= range.min && container.securityContext.runAsUser <= range.max) :
                          variables.podRunAsUser == null || !variables.params.runAsUser.ranges.exists(range, variables.podRunAsUser >= range.min && variables.podRunAsUser <= range.max)
                      ) : false
                    )
                  )
                ) : false
              )
          - name: missingRequiredRunAsGroupEphemeralContainers
            expression: |
              variables.ephemeralContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.runAsGroup) && has(variables.params.runAsGroup.rule) && (variables.params.runAsGroup.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.runAsGroup)) || 
                  (variables.podRunAsGroup != null))
              )
          - name: invalidRunAsGroupEphemeralContainers
            expression: |
              variables.ephemeralContainers.filter(container, 
                !(container.image in variables.exemptImages) && 
                !(variables.missingRequiredRunAsGroupEphemeralContainers.exists(c, c.name == container.name)) &&
                (
                  has(variables.params.runAsGroup) && has(variables.params.runAsGroup.rule) ? 
                  (
                    variables.params.runAsGroup.rule == "RunAsAny" ? false :
                    (
                      (variables.params.runAsGroup.rule == "MustRunAs" || variables.params.runAsGroup.rule == "MayRunAs") && 
                      (
                        has(container.securityContext) && has(container.securityContext.runAsGroup) ? 
                          !variables.params.runAsGroup.ranges.exists(range, container.securityContext.runAsGroup >= range.min && container.securityContext.runAsGroup <= range.max) : 
                          variables.podRunAsGroup == null || !variables.params.runAsGroup.ranges.exists(range, variables.podRunAsGroup >= range.min && variables.podRunAsGroup <= range.max)
                      )
                    )
                  )
                  : false
                )
              )
          - name: missingRequiredFsGroupEphemeralContainers
            expression: |
              variables.ephemeralContainers.filter(container, 
                has(variables.params.fsGroup) && has(variables.params.fsGroup.rule) && (variables.params.fsGroup.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.fsGroup)) || 
                  (variables.podRunAsFsGroup != null))
              )
          - name: invalidRunAsFsGroupEphemeralContainers
            expression: |
              variables.ephemeralContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                !(variables.missingRequiredFsGroupEphemeralContainers.exists(c, c.name == container.name)) &&
                (
                  has(variables.params.fsGroup) && has(variables.params.fsGroup.rule) ? 
                  (
                    variables.params.fsGroup.rule == "RunAsAny" ? false :
                    (
                      (variables.params.fsGroup.rule == "MustRunAs" || variables.params.fsGroup.rule == "MayRunAs") && 
                      (
                        has(container.securityContext) && has(container.securityContext.fsGroup) ? 
                          !variables.params.fsGroup.ranges.exists(range, container.securityContext.fsGroup >= range.min && container.securityContext.fsGroup <= range.max) : 
                          variables.podRunAsFsGroup == null || !variables.params.fsGroup.ranges.exists(range, variables.podRunAsFsGroup >= range.min && variables.podRunAsFsGroup <= range.max)
                      )
                    )
                  )
                  : false
                )
              )
          - name: missingRequiredSupplementalGroupsEphemeralContainers
            expression: |
              variables.ephemeralContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                has(variables.params.supplementalGroups) && has(variables.params.supplementalGroups.rule) && (variables.params.supplementalGroups.rule == "MustRunAs") &&
                !((has(container.securityContext) && has(container.securityContext.supplementalGroups)) || 
                  (variables.podRunAsSupplementalGroups != null)))
          - name: invalidSupplimentalGroupsEphemeralContainers
            expression: |
              variables.ephemeralContainers.filter(container, 
                !(container.image in variables.exemptImages) &&
                !(variables.missingRequiredSupplementalGroupsEphemeralContainers.exists(c, c.name == container.name)) &&
                (
                  has(variables.params.supplementalGroups) && has(variables.params.supplementalGroups.rule) ? 
                  (
                    variables.params.supplementalGroups.rule == "RunAsAny" ? false :
                    (
                      (variables.params.supplementalGroups.rule == "MustRunAs" || variables.params.supplementalGroups.rule == "MayRunAs") && 
                      (
                        has(container.securityContext) && has(container.securityContext.supplementalGroups) ? 
                          !variables.params.supplementalGroups.ranges.exists(range, container.securityContext.supplementalGroups.all(gp, gp>= range.min && gp <= range.max)) : 
                          variables.podRunAsSupplementalGroups == null || !variables.params.supplementalGroups.ranges.exists(range, variables.podRunAsSupplementalGroups.all(gp, gp >= range.min && gp <= range.max))
                      )
                    )
                  )
                  : false
                )
              )
          validations:
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredRunAsUserContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredRunAsUserContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/runAsUser"'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredRunAsNonRootContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredRunAsNonRootContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/runAsNonRoot or securityContext/runAsUser != 0"'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.invalidRunAsUserContainers) == 0'
            messageExpression: '"Containers " + variables.invalidRunAsUserContainers.map(c, c.name).join(", ") + " are attempting to run as disallowed user. Allowed runAsUser: " + variables.params.runAsUser.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredRunAsGroupContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredRunAsGroupContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/runAsGroup. Allowed runAsGroup: " + variables.params.runAsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.invalidRunAsGroupContainers) == 0'
            messageExpression: '"Containers " + variables.invalidRunAsGroupContainers.map(c, c.name).join(", ") + " are attempting to run as disallowed group. Allowed runAsGroup: " + variables.params.runAsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredFsGroupContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredFsGroupContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/fsGroup. Allowed fsGroup: " + variables.params.fsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.invalidRunAsFsGroupContainers) == 0'
            messageExpression: '"Containers " + variables.invalidRunAsFsGroupContainers.map(c, c.name).join(", ") + " are attempting to run as disallowed fsGroup. Allowed fsGroup: " + variables.params.fsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredSupplementalGroupsContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredSupplementalGroupsContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/supplementalGroups. Allowed supplementalGroups: " + variables.params.supplementalGroups.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredRunAsUserInitContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredRunAsUserInitContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/runAsUser"'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredRunAsNonRootInitContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredRunAsNonRootInitContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/runAsNonRoot or securityContext/runAsUser != 0"'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.invalidRunAsUserInitContainers) == 0'
            messageExpression: '"Containers " + variables.invalidRunAsUserInitContainers.map(c, c.name).join(", ") + " are attempting to run as disallowed user. Allowed runAsUser: " + variables.params.runAsUser.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredRunAsGroupInitContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredRunAsGroupInitContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/runAsGroup. Allowed runAsGroup: " + variables.params.runAsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.invalidRunAsGroupInitContainers) == 0'
            messageExpression: '"Containers " + variables.invalidRunAsGroupInitContainers.map(c, c.name).join(", ") + " are attempting to run as disallowed group. Allowed runAsGroup: " + variables.params.runAsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredFsGroupInitContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredFsGroupInitContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/fsGroup. Allowed fsGroup: " + variables.params.fsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.invalidRunAsFsGroupInitContainers) == 0'
            messageExpression: '"Containers " + variables.invalidRunAsFsGroupInitContainers.map(c, c.name).join(", ") + " are attempting to run as disallowed fsGroup. Allowed fsGroup: " + variables.params.fsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredSupplementalGroupsInitContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredSupplementalGroupsInitContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/supplementalGroups. Allowed supplementalGroups: " + variables.params.supplementalGroups.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredRunAsUserEphemeralContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredRunAsUserEphemeralContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/runAsUser"'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredRunAsNonRootEphemeralContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredRunAsNonRootEphemeralContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/runAsNonRoot or securityContext/runAsUser != 0"'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.invalidRunAsUserEphemeralContainers) == 0'
            messageExpression: '"Containers " + variables.invalidRunAsUserEphemeralContainers.map(c, c.name).join(", ") + " are attempting to run as disallowed user. Allowed runAsUser: " + variables.params.runAsUser.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredRunAsGroupEphemeralContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredRunAsGroupEphemeralContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/runAsGroup. Allowed runAsGroup: " + variables.params.runAsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.invalidRunAsGroupEphemeralContainers) == 0'
            messageExpression: '"Containers " + variables.invalidRunAsGroupEphemeralContainers.map(c, c.name).join(", ") + " are attempting to run as disallowed group. Allowed runAsGroup: " + variables.params.runAsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredFsGroupEphemeralContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredFsGroupEphemeralContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/fsGroup. Allowed fsGroup: " + variables.params.fsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.invalidRunAsFsGroupEphemeralContainers) == 0'
            messageExpression: '"Containers " + variables.invalidRunAsFsGroupEphemeralContainers.map(c, c.name).join(", ") + " are attempting to run as disallowed fsGroup. Allowed fsGroup: " + variables.params.fsGroup.ranges.map(range, range.min + "-" + range.max).join(", ")'
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.missingRequiredSupplementalGroupsEphemeralContainers) == 0'
            messageExpression: '"Containers " + variables.missingRequiredSupplementalGroupsEphemeralContainers.map(c, c.name).join(", ") + " are attempting to run without a required securityContext/supplementalGroups. Allowed supplementalGroups: " + variables.params.supplementalGroups.ranges.map(range, range.min + "-" + range.max).join(", ")'
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
              review.kind.kind == "Pod"
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
    - name: nginx
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


</details>