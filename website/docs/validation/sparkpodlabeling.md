---
id: sparkpodlabeling
title: Spark Pod Labeling
---

# Spark Pod Labeling

## Description
Enforces security and labeling requirements for Spark pods created by Spark service accounts. Validates that Spark pods have required labels (spark-job-id, spark-role), use allowed service accounts, run only approved container images, and follow security best practices by prohibiting privileged containers and host path volumes.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: sparkpodlabeling
  annotations:
    metadata.gatekeeper.sh/title: "Spark Pod Labeling"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Enforces security and labeling requirements for Spark pods created by Spark service accounts.
      Validates that Spark pods have required labels (spark-job-id, spark-role), use allowed
      service accounts, run only approved container images, and follow security best practices
      by prohibiting privileged containers and host path volumes.
spec:
  crd:
    spec:
      names:
        kind: SparkPodLabeling
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedServiceAccounts:
              type: array
              items:
                type: string
            requiredLabels:
              type: array
              items:
                type: string
            allowedImagePatterns:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
            package sparkpodlabeling

            # Check if this is a Spark service account
            is_spark_service_account {
                some i
                input.review.object.spec.serviceAccountName == input.parameters.allowedServiceAccounts[i]
            }

            # Violation: Spark service account creating pod without required labels
            violation[{"msg": msg}] {
                is_spark_service_account
                some j
                required := input.parameters.requiredLabels[j]
                not input.review.object.metadata.labels[required]
                msg := sprintf("Spark pod missing required label: %v", [required])
            }

            # Violation: Spark service account creating pod with empty spark-job-id
            violation[{"msg": msg}] {
                is_spark_service_account
                job_id := input.review.object.metadata.labels["spark-job-id"]
                job_id == ""
                msg := "spark-job-id label cannot be empty"
            }

            # Violation: Spark service account creating pod without spark-role
            violation[{"msg": msg}] {
                is_spark_service_account
                role := input.review.object.metadata.labels["spark-role"]
                not role
                msg := "spark-role label is required (driver or executor)"
            }

            # Violation: Invalid spark-role value
            violation[{"msg": msg}] {
                is_spark_service_account
                role := input.review.object.metadata.labels["spark-role"]
                not role == "driver"
                not role == "executor"
                msg := sprintf("Invalid spark-role: %v. Must be 'driver' or 'executor'", [role])
            }

            # Violation: Spark service account using non-Spark images
            violation[{"msg": msg}] {
                is_spark_service_account
                some k
                image := input.review.object.spec.containers[k].image
                allowed_patterns := input.parameters.allowedImagePatterns
                count([p | some l; p := allowed_patterns[l]; contains(image, p)]) == 0
                msg := sprintf("Image not allowed for Spark pods: %v", [image])
            }

            # Violation: Spark service account creating pods with privileged containers
            violation[{"msg": msg}] {
                is_spark_service_account
                some m
                input.review.object.spec.containers[m].securityContext.privileged == true
                msg := "Privileged containers not allowed for Spark pods"
            }

            # Violation: Spark service account mounting host paths
            violation[{"msg": msg}] {
                is_spark_service_account
                some n
                input.review.object.spec.volumes[n].hostPath
                msg := "Host path volumes not allowed for Spark pods"
            }

            # Violation: Executors must use same service account as driver
            violation[{"msg": msg}] {
                is_spark_service_account
                role := input.review.object.metadata.labels["spark-role"]
                role == "executor"
                executor_sa := input.review.object.spec.serviceAccountName
                count([sa | some o; sa := input.parameters.allowedServiceAccounts[o]; sa == executor_sa]) == 0
                msg := sprintf("SECURITY: Executor pod must use allowed service account. Found: %v", [executor_sa])
            }

            # Violation: Drivers creating pods with different service account
            violation[{"msg": msg}] {
                is_spark_service_account
                pod_sa := input.review.object.spec.serviceAccountName
                count([sa | some p; sa := input.parameters.allowedServiceAccounts[p]; sa == pod_sa]) == 0
                msg := sprintf("SECURITY: Pod service account '%v' must match allowed service accounts", [pod_sa])
            }
            

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/template.yaml
```
## Examples
<details>
<summary>spark-pod-labeling</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: SparkPodLabeling
metadata:
  name: spark-pod-labeling
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowedServiceAccounts:
      - "spark-driver-sa"
      - "spark-executor-sa"
    requiredLabels:
      - "spark-job-id"
      - "spark-role"
      - "app"
    allowedImagePatterns:
      - "spark/"
      - "apache/spark"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/constraint.yaml
```

</details>

<details>
<summary>valid-spark-driver</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-driver-pod
  labels:
    spark-job-id: "job-123"
    spark-role: "driver"
    app: "spark-app"
spec:
  serviceAccountName: "spark-driver-sa"
  containers:
    - name: spark-driver
      image: "spark/spark:3.4.0"
      command: ["spark-submit"]
      args: ["--class", "MySparkApp", "myapp.jar"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_valid_driver.yaml
```

</details>
<details>
<summary>valid-spark-executor</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-executor-pod
  labels:
    spark-job-id: "job-123"
    spark-role: "executor"
    app: "spark-app"
spec:
  serviceAccountName: "spark-executor-sa"
  containers:
    - name: spark-executor
      image: "apache/spark:3.4.0"
      command: ["spark-executor"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_valid_executor.yaml
```

</details>
<details>
<summary>missing-required-label</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-pod-missing-label
  labels:
    spark-job-id: "job-123"
    spark-role: "driver"
    # Missing required "app" label
spec:
  serviceAccountName: "spark-driver-sa"
  containers:
    - name: spark-driver
      image: "spark/spark:3.4.0"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_missing_label.yaml
```

</details>
<details>
<summary>empty-spark-job-id</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-pod-empty-job-id
  labels:
    spark-job-id: ""
    spark-role: "driver"
    app: "spark-app"
spec:
  serviceAccountName: "spark-driver-sa"
  containers:
    - name: spark-driver
      image: "spark/spark:3.4.0"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_empty_job_id.yaml
```

</details>
<details>
<summary>missing-spark-role</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-pod-missing-role
  labels:
    spark-job-id: "job-123"
    app: "spark-app"
    # Missing spark-role label
spec:
  serviceAccountName: "spark-driver-sa"
  containers:
    - name: spark-driver
      image: "spark/spark:3.4.0"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_missing_role.yaml
```

</details>
<details>
<summary>invalid-spark-role</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-pod-invalid-role
  labels:
    spark-job-id: "job-123"
    spark-role: "invalid-role"
    app: "spark-app"
spec:
  serviceAccountName: "spark-driver-sa"
  containers:
    - name: spark-driver
      image: "spark/spark:3.4.0"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_invalid_role.yaml
```

</details>
<details>
<summary>disallowed-image</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-pod-disallowed-image
  labels:
    spark-job-id: "job-123"
    spark-role: "driver"
    app: "spark-app"
spec:
  serviceAccountName: "spark-driver-sa"
  containers:
    - name: spark-driver
      image: "nginx:latest"  # Not allowed for Spark pods

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_disallowed_image.yaml
```

</details>
<details>
<summary>privileged-container</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-pod-privileged
  labels:
    spark-job-id: "job-123"
    spark-role: "driver"
    app: "spark-app"
spec:
  serviceAccountName: "spark-driver-sa"
  containers:
    - name: spark-driver
      image: "spark/spark:3.4.0"
      securityContext:
        privileged: true  # Not allowed for Spark pods

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_privileged_container.yaml
```

</details>
<details>
<summary>host-path-volume</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-pod-host-path
  labels:
    spark-job-id: "job-123"
    spark-role: "driver"
    app: "spark-app"
spec:
  serviceAccountName: "spark-driver-sa"
  containers:
    - name: spark-driver
      image: "spark/spark:3.4.0"
  volumes:
    - name: host-vol
      hostPath:
        path: "/tmp"  # Not allowed for Spark pods

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_host_path_volume.yaml
```

</details>
<details>
<summary>wrong-service-account</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-pod-wrong-sa
  labels:
    spark-job-id: "job-123"
    spark-role: "driver"
    app: "spark-app"
spec:
  serviceAccountName: "wrong-sa"  # Not in allowed list
  containers:
    - name: spark-driver
      image: "spark/spark:3.4.0"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_wrong_service_account.yaml
```

</details>
<details>
<summary>executor-wrong-service-account</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-executor-wrong-sa
  labels:
    spark-job-id: "job-123"
    spark-role: "executor"
    app: "spark-app"
spec:
  serviceAccountName: "wrong-sa"  # Not in allowed list
  containers:
    - name: spark-executor
      image: "spark/spark:3.4.0"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_executor_wrong_sa.yaml
```

</details>
<details>
<summary>non-spark-service-account</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: regular-pod
  labels:
    app: "nginx"
spec:
  serviceAccountName: "regular-sa"  # Not a Spark service account
  containers:
    - name: nginx
      image: "nginx:latest"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_non_spark_sa.yaml
```

</details>
<details>
<summary>multiple-violations</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spark-pod-multiple-violations
  labels:
    spark-job-id: ""  # Empty job ID
    spark-role: "invalid-role"  # Invalid role
    # Missing required "app" label
spec:
  serviceAccountName: "spark-driver-sa"
  containers:
    - name: spark-driver
      image: "nginx:latest"  # Disallowed image
      securityContext:
        privileged: true  # Privileged container
  volumes:
    - name: host-vol
      hostPath:
        path: "/tmp"  # Host path volume

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/sparkpodlabeling/samples/spark-pod-labeling/example_multiple_violations.yaml
```

</details>


</details>