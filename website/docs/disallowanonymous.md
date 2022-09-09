---
id: disallowanonymous
title: Disallow Anonymous Access
---

# Disallow Anonymous Access

## Description
Disallows associating ClusterRole and Role resources to the system:anonymous user and system:unauthenticated group.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowanonymous
  annotations:
    metadata.gatekeeper.sh/title: "Disallow Anonymous Access"
    description: Disallows associating ClusterRole and Role resources to the system:anonymous user and system:unauthenticated group.
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowAnonymous
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            allowedRoles:
              description: >-
                The list of ClusterRoles and Roles that may be associated
                with the `system:unauthenticated` group and `system:anonymous`
                user.
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdisallowanonymous

        violation[{"msg": msg}] {
          not is_allowed(input.review.object.roleRef, input.parameters.allowedRoles)
          review(input.review.object.subjects[_])
          msg := sprintf("Unauthenticated user reference is not allowed in %v %v ", [input.review.object.kind, input.review.object.metadata.name])
        }

        is_allowed(role, allowedRoles) {
          role.name == allowedRoles[_]
        }

        review(subject) = true {
          subject.name == "system:unauthenticated"
        }

        review(subject) = true {
          subject.name == "system:anonymous"
        }

```

## Examples
<details>
<summary>disallow-anonymous</summary><blockquote>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDisallowAnonymous
metadata:
  name: no-anonymous
spec:
  match:
    kinds:
      - apiGroups: ["rbac.authorization.k8s.io"]
        kinds: ["ClusterRoleBinding"]
      - apiGroups: ["rbac.authorization.k8s.io"]
        kinds: ["RoleBinding"]
  parameters:
    allowedRoles: 
      - cluster-role-1

```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-role-binding-1
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-role-1
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:authenticated
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:unauthenticated

```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-role-binding-2
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-role-2
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:authenticated
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:unauthenticated

```

</details>


</blockquote></details>