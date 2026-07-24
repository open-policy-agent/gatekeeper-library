---
id: requiredprobes
title: Required Probes
---

# Required Probes

## Description
Requires Pods to have readiness and/or liveness probes.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredprobes
  annotations:
    metadata.gatekeeper.sh/title: "Required Probes"
    metadata.gatekeeper.sh/version: 1.0.1
    description: Requires Pods to have readiness and/or liveness probes.
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredProbes
      validation:
        openAPIV3Schema:
          type: object
          properties:
            probes:
              description: "A list of probes that are required (ex: `readinessProbe`)"
              type: array
              items:
                type: string
            probeTypes:
              description: "The probe must define a field listed in `probeType` in order to satisfy the constraint (ex. `tcpSocket` satisfies `['tcpSocket', 'exec']`)"
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredprobes

        import data.lib.exclude_update.is_update

        probe_type_set = probe_types {
            probe_types := {type | type := input.parameters.probeTypes[_]}
        }

        violation[{"msg": msg}] {
            # Probe fields are immutable.
            not is_update(input.review)

            container := input.review.object.spec.containers[_]
            probe := input.parameters.probes[_]
            probe_is_missing(container, probe)
            msg := get_violation_message(container, input.review, probe)
        }

        probe_is_missing(ctr, probe) = true {
            not ctr[probe]
        }

        probe_is_missing(ctr, probe) = true {
            probe_field_empty(ctr, probe)
        }

        probe_field_empty(ctr, probe) = true {
            probe_fields := {field | ctr[probe][field]}
            diff_fields := probe_type_set - probe_fields
            count(diff_fields) == count(probe_type_set)
        }

        get_violation_message(container, review, probe) = msg {
            msg := sprintf("Container <%v> in your <%v> <%v> has no <%v>", [container.name, review.kind.kind, review.object.metadata.name, probe])
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredprobes/template.yaml
```
## Examples
<details>
<summary>required-probes</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredProbes
metadata:
  name: must-have-probes
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    probes: ["readinessProbe", "livenessProbe"]
    probeTypes: ["tcpSocket", "httpGet", "exec"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredprobes/samples/must-have-probes/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod1
spec:
  containers:
  - name: tomcat
    image: tomcat
    ports:
    - containerPort: 8080
    livenessProbe:
      tcpSocket:
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    readinessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
  volumes:
  - name: cache-volume
    emptyDir: {}

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredprobes/samples/must-have-probes/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod1
spec:
  containers:
  - name: nginx-1
    image: nginx:1.7.9
    ports:
    - containerPort: 80
    livenessProbe:
      # tcpSocket:
      #   port: 80
      # initialDelaySeconds: 5
      # periodSeconds: 10
    volumeMounts:
    - mountPath: /tmp/cache
      name: cache-volume
  - name: tomcat
    image: tomcat
    ports:
    - containerPort: 8080
    readinessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
  volumes:
  - name: cache-volume
    emptyDir: {}

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredprobes/samples/must-have-probes/example_disallowed.yaml
```

</details>
<details>
<summary>example-disallowed2</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod2
spec:
  containers:
  - name: nginx-1
    image: nginx:1.7.9
    ports:
    - containerPort: 80
    readinessProbe:
    # httpGet:
    #   path: /
    #   port: 80
    # initialDelaySeconds: 5
    # periodSeconds: 10
    livenessProbe:
      tcpSocket:
        port: 80
      initialDelaySeconds: 5
      periodSeconds: 10
    volumeMounts:
    - mountPath: /tmp/cache
      name: cache-volume
  - name: tomcat
    image: tomcat
    ports:
    - containerPort: 8080
    readinessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
    # livenessProbe:
    #   tcpSocket:
    #     port: 8080
    #   initialDelaySeconds: 5
    #   periodSeconds: 10
  volumes:
  - name: cache-volume
    emptyDir: {}

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredprobes/samples/must-have-probes/example_disallowed2.yaml
```

</details>


</details>