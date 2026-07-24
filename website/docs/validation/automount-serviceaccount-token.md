---
id: automount-serviceaccount-token
title: Automount Service Account Token for Pod
---

# Automount Service Account Token for Pod

## Description
Controls the ability of any Pod to enable automountServiceAccountToken.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspautomountserviceaccounttokenpod
  annotations:
    metadata.gatekeeper.sh/title: "Automount Service Account Token for Pod"
    metadata.gatekeeper.sh/version: 1.0.1
    description: >-
      Controls the ability of any Pod to enable automountServiceAccountToken.
spec:
  crd:
    spec:
      names:
        kind: K8sPSPAutomountServiceAccountTokenPod
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Controls the ability of any Pod to enable automountServiceAccountToken.
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sautomountserviceaccounttoken

        import data.lib.exclude_update.is_update

        violation[{"msg": msg}] {
            # spec.automountServiceAccountToken and spec.containers.volumeMounts fields are immutable.
            not is_update(input.review)

            obj := input.review.object
            mountServiceAccountToken(obj.spec)
            msg := sprintf("Automounting service account token is disallowed, pod: %v", [obj.metadata.name])
        }

        mountServiceAccountToken(spec) {
            spec.automountServiceAccountToken == true
        }

        # if there is no automountServiceAccountToken spec, check on volumeMount in containers. Service Account token is mounted on /var/run/secrets/kubernetes.io/serviceaccount
        # https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#serviceaccount-admission-controller
        mountServiceAccountToken(spec) {
            not has_key(spec, "automountServiceAccountToken")
            "/var/run/secrets/kubernetes.io/serviceaccount" == input_containers[_].volumeMounts[_].mountPath
        }

        input_containers[c] {
            c := input.review.object.spec.containers[_]
        }

        input_containers[c] {
            c := input.review.object.spec.initContainers[_]
        }

        # Ephemeral containers not checked as it is not possible to set field.

        has_key(x, k) {
            _ = x[k]
        }
      libs:
        - |
          package lib.exclude_update

          is_update(review) {
              review.operation == "UPDATE"
          }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/automount-serviceaccount-token/template.yaml
```
## Examples
<details>
<summary>automount-serviceaccount-token</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPAutomountServiceAccountTokenPod
metadata:
  name: psp-automount-serviceaccount-token-pod
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/automount-serviceaccount-token/samples/automount-serviceaccount-token/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-automountserviceaccounttoken-allowed
  labels:
    app: nginx-not-automountserviceaccounttoken
spec:
  automountServiceAccountToken: false
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/automount-serviceaccount-token/samples/automount-serviceaccount-token/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-automountserviceaccounttoken-disallowed
  labels:
    app: nginx-automountserviceaccounttoken
spec:
  automountServiceAccountToken: true
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/automount-serviceaccount-token/samples/automount-serviceaccount-token/example_disallowed.yaml
```

</details>


</details>