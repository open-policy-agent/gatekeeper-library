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
    