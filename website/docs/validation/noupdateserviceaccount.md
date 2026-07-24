---
id: noupdateserviceaccount
title: Block updating Service Account
---

# Block updating Service Account

## Description
Blocks updating the service account on resources that abstract over Pods. This policy is ignored in audit mode.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: noupdateserviceaccount
  annotations:
    metadata.gatekeeper.sh/title: "Block updating Service Account"
    metadata.gatekeeper.sh/version: 1.0.1
    description: "Blocks updating the service account on resources that abstract over Pods. This policy is ignored in audit mode."
spec:
  crd:
    spec:
      names:
        kind: NoUpdateServiceAccount
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedGroups:
              description: Groups that should be allowed to bypass the policy.
              type: array
              items:
                type: string
            allowedUsers:
              description: Users that should be allowed to bypass the policy.
              type: array
              items:
                type: string
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package noupdateserviceaccount

      privileged(userInfo, allowedUsers, _) {
        # Allow if the user is in allowedUsers.
        # Use object.get so omitted parameters can't cause policy bypass by
        # evaluating to undefined.
        username := object.get(userInfo, "username", "")
        allowedUsers[_] == username
      }

      privileged(userInfo, _, allowedGroups) {
        # Allow if the user's groups intersect allowedGroups.
        # Use object.get so omitted parameters can't cause policy bypass by
        # evaluating to undefined.
        userGroups := object.get(userInfo, "groups", [])
        groups := {g | g := userGroups[_]}
        allowed := {g | g := allowedGroups[_]}
        intersection := groups & allowed
        count(intersection) > 0
      }

      get_service_account(obj) = spec {
        obj.kind == "Pod"
        spec := obj.spec.serviceAccountName
      } {
        obj.kind == "ReplicationController"
        spec := obj.spec.template.spec.serviceAccountName
      } {
        obj.kind == "ReplicaSet"
        spec := obj.spec.template.spec.serviceAccountName
      } {
        obj.kind == "Deployment"
        spec := obj.spec.template.spec.serviceAccountName
      } {
        obj.kind == "StatefulSet"
        spec := obj.spec.template.spec.serviceAccountName
      } {
        obj.kind == "DaemonSet"
        spec := obj.spec.template.spec.serviceAccountName
      } {
        obj.kind == "Job"
        spec := obj.spec.template.spec.serviceAccountName
      } {
        obj.kind == "CronJob"
        spec := obj.spec.jobTemplate.spec.template.spec.serviceAccountName
      }

      violation[{"msg": msg}] {
        # This policy only applies to updates of existing resources.
        input.review.operation == "UPDATE"

        # Use object.get so omitted parameters can't cause policy bypass by
        # evaluating to undefined.
        params := object.get(input, "parameters", {})
        allowedUsers := object.get(params, "allowedUsers", [])
        allowedGroups := object.get(params, "allowedGroups", [])

        # Extract the service account.
        oldKSA := get_service_account(input.review.oldObject)
        newKSA := get_service_account(input.review.object)

        # Deny unprivileged users and groups from changing serviceAccountName.
        not privileged(input.review.userInfo, allowedUsers, allowedGroups)
        oldKSA != newKSA
        msg := "user does not have permission to modify serviceAccountName"
      } {
        # Defensively require object to have a serviceAccountName.
        input.review.operation == "UPDATE"
        not get_service_account(input.review.object)
        msg := "missing serviceAccountName field in object under review"
      } {
        # Defensively require oldObject to have a serviceAccountName.
        input.review.operation == "UPDATE"
        not get_service_account(input.review.oldObject)
        msg := "missing serviceAccountName field in oldObject under review"
      }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/noupdateserviceaccount/template.yaml
```
## Examples
<details>
<summary>noupdateserviceaccount</summary>

<details>
<summary>constraint</summary>

```yaml
# IMPORTANT: Before deploying this policy, make sure you allow-list any groups
# or users that need to deploy workloads to kube-system, such as cluster-
# lifecycle controllers, addon managers, etc. Such controllers may need to
# update service account names during automated rollouts (e.g. of refactored
# configurations). You can allow-list them with the allowedGroups and
# allowedUsers properties of the NoUpdateServiceAccount Constraint.
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: NoUpdateServiceAccount
metadata:
  name: no-update-kube-system-service-account
spec:
  match:
    namespaces: ["kube-system"]
    kinds:
    - apiGroups: [""]
      kinds:
      # You can optionally add "Pod" here, but it is unnecessary because
      # Pod service account immutability is enforced by the Kubernetes API.
      - "ReplicationController"
    - apiGroups: ["apps"]
      kinds:
      - "ReplicaSet"
      - "Deployment"
      - "StatefulSet"
      - "DaemonSet"
    - apiGroups: ["batch"]
      kinds:
      # You can optionally add "Job" here, but it is unnecessary because
      # Job service account immutability is enforced by the Kubernetes API.
      - "CronJob"
  parameters:
    allowedGroups: []
    allowedUsers: []

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/noupdateserviceaccount/samples/noupdateserviceaccount/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
# Note: The gator tests currently require exactly one object per example file.
# Since this is an update-triggered policy, at least two objects are technically
# required to demonstrate it. Due to the gator requirement, we only have one
# object below. The policy should allow changing everything but the
# serviceAccountName field.
kind: Deployment
apiVersion: apps/v1
metadata:
  name: policy-test
  namespace: kube-system
  labels:
    app: policy-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: policy-test-deploy
  template:
    metadata:
      labels:
        app: policy-test-deploy
    spec:
      # Changing anything except this field should be allowed by the policy.
      serviceAccountName: policy-test-sa-1
      containers:
      - name: policy-test
        image: ubuntu
        command:
        - /bin/bash
        - -c
        - sleep 99999

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/noupdateserviceaccount/samples/noupdateserviceaccount/example_allowed.yaml
```

</details>


</details>