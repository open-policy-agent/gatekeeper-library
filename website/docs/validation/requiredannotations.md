---
id: requiredannotations
title: Required Annotations
---

# Required Annotations

## Description
Requires resources to contain specified annotations, with values matching provided regular expressions.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredannotations
  annotations:
    metadata.gatekeeper.sh/title: "Required Annotations"
    metadata.gatekeeper.sh/version: 1.0.1
    description: >-
      Requires resources to contain specified annotations, with values matching
      provided regular expressions.
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredAnnotations
      validation:
        openAPIV3Schema:
          type: object
          properties:
            message:
              type: string
            annotations:
              type: array
              description: >-
                A list of annotations and values the object must specify.
              items:
                type: object
                properties:
                  key:
                    type: string
                    description: >-
                      The required annotation.
                  allowedRegex:
                    type: string
                    description: >-
                      If specified, a regular expression the annotation's value
                      must match. The value must contain at least one match for
                      the regular expression.
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredannotations

        violation[{"msg": msg, "details": {"missing_annotations": missing}}] {
            provided := {annotation | input.review.object.metadata.annotations[annotation]}
            required := {annotation | annotation := input.parameters.annotations[_].key}
            missing := required - provided
            count(missing) > 0
            msg := sprintf("you must provide annotation(s): %v", [missing])
        }

        violation[{"msg": msg}] {
          value := input.review.object.metadata.annotations[key]
          expected := input.parameters.annotations[_]
          expected.key == key
          expected.allowedRegex != ""
          not regex.match(expected.allowedRegex, value)
          msg := sprintf("Annotation <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredannotations/template.yaml
```
## Examples
<details>
<summary>must-have-set-of-annotations</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredAnnotations
metadata:
  name: all-must-have-certain-set-of-annotations
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Service"]
  parameters:
    message: "All services must have a `a8r.io/owner` and `a8r.io/runbook` annotations."
    annotations:
      - key: a8r.io/owner
        # Matches email address or github user
        allowedRegex: ^([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}|[a-z]{1,39})$
      - key: a8r.io/runbook
        # Matches urls including or not http/https
        allowedRegex: ^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredannotations/samples/all-must-have-certain-set-of-annotations/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Service
metadata:
  name: allowed-service
  annotations:
    a8r.io/owner: "dev-team-alfa@contoso.com"
    a8r.io/runbook: "https://confluence.contoso.com/dev-team-alfa/runbooks"
spec:
  ports:
  - name: http
    port: 80
    targetPort: 8080
  selector:
    app: foo

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredannotations/samples/all-must-have-certain-set-of-annotations/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Service
metadata:
  name: disallowed-service
spec:
  ports:
  - name: http
    port: 80
    targetPort: 8080
  selector:
    app: foo

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredannotations/samples/all-must-have-certain-set-of-annotations/example_disallowed.yaml
```

</details>


</details>