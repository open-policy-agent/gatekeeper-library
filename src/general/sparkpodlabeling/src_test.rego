package sparkpodlabeling

# Test valid Spark driver pod with all required labels and proper service account
test_valid_spark_driver {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-driver-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "driver",
                "app": "spark-app"
            },
            "containers": [{"image": "spark/spark:3.4.0"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa", "spark-executor-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/", "apache/spark"]
        }
    }
    results := violation with input as inp
    count(results) == 0
}

# Test valid Spark executor pod with all required labels and proper service account
test_valid_spark_executor {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-executor-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "executor",
                "app": "spark-app"
            },
            "containers": [{"image": "spark/spark:3.4.0"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa", "spark-executor-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/", "apache/spark"]
        }
    }
    results := violation with input as inp
    count(results) == 0
}

# Test missing required label
test_missing_required_label {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-driver-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "driver"
                # Missing "app" label
            },
            "containers": [{"image": "spark/spark:3.4.0"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/"]
        }
    }
    results := violation with input as inp
    count(results) == 1
    results[0].msg == "Spark pod missing required label: app"
}

# Test empty spark-job-id
test_empty_spark_job_id {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-driver-sa",
            "labels": {
                "spark-job-id": "",
                "spark-role": "driver",
                "app": "spark-app"
            },
            "containers": [{"image": "spark/spark:3.4.0"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/"]
        }
    }
    results := violation with input as inp
    count(results) == 1
    results[0].msg == "spark-job-id label cannot be empty"
}

# Test missing spark-role
test_missing_spark_role {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-driver-sa",
            "labels": {
                "spark-job-id": "job-123",
                "app": "spark-app"
                # Missing spark-role
            },
            "containers": [{"image": "spark/spark:3.4.0"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/"]
        }
    }
    results := violation with input as inp
    count(results) == 1
    results[0].msg == "spark-role label is required (driver or executor)"
}

# Test invalid spark-role
test_invalid_spark_role {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-driver-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "invalid-role",
                "app": "spark-app"
            },
            "containers": [{"image": "spark/spark:3.4.0"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/"]
        }
    }
    results := violation with input as inp
    count(results) == 1
    results[0].msg == "Invalid spark-role: invalid-role. Must be 'driver' or 'executor'"
}

# Test disallowed image
test_disallowed_image {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-driver-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "driver",
                "app": "spark-app"
            },
            "containers": [{"image": "nginx:latest"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/", "apache/spark"]
        }
    }
    results := violation with input as inp
    count(results) == 1
    results[0].msg == "Image not allowed for Spark pods: nginx:latest"
}

# Test privileged container
test_privileged_container {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-driver-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "driver",
                "app": "spark-app"
            },
            "containers": [{
                "image": "spark/spark:3.4.0",
                "securityContext": {"privileged": true}
            }]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/"]
        }
    }
    results := violation with input as inp
    count(results) == 1
    results[0].msg == "Privileged containers not allowed for Spark pods"
}

# Test host path volume
test_host_path_volume {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-driver-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "driver",
                "app": "spark-app"
            },
            "containers": [{"image": "spark/spark:3.4.0"}],
            "volumes": [{"name": "host-vol", "hostPath": {"path": "/tmp"}}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/"]
        }
    }
    results := violation with input as inp
    count(results) == 1
    results[0].msg == "Host path volumes not allowed for Spark pods"
}

# Test executor with wrong service account
test_executor_wrong_service_account {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "wrong-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "executor",
                "app": "spark-app"
            },
            "containers": [{"image": "spark/spark:3.4.0"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa", "spark-executor-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/"]
        }
    }
    results := violation with input as inp
    count(results) == 1
    results[0].msg == "SECURITY: Executor pod must use allowed service account. Found: wrong-sa"
}

# Test driver with wrong service account
test_driver_wrong_service_account {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "wrong-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "driver",
                "app": "spark-app"
            },
            "containers": [{"image": "spark/spark:3.4.0"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa", "spark-executor-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/"]
        }
    }
    results := violation with input as inp
    count(results) == 1
    results[0].msg == "SECURITY: Pod service account 'wrong-sa' must match allowed service accounts"
}

# Test non-Spark service account (should pass)
test_non_spark_service_account {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "regular-sa",
            "labels": {
                "app": "nginx"
            },
            "containers": [{"image": "nginx:latest"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa", "spark-executor-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/"]
        }
    }
    results := violation with input as inp
    count(results) == 0
}

# Test multiple violations
test_multiple_violations {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "wrong-sa",
            "labels": {
                "spark-job-id": "",
                "spark-role": "invalid-role"
                # Missing required "app" label
            },
            "containers": [{
                "image": "nginx:latest",
                "securityContext": {"privileged": true}
            }],
            "volumes": [{"name": "host-vol", "hostPath": {"path": "/tmp"}}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/"]
        }
    }
    results := violation with input as inp
    count(results) >= 5  # Should have multiple violations
}

# Test valid image patterns
test_valid_image_patterns {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-driver-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "driver",
                "app": "spark-app"
            },
            "containers": [{"image": "apache/spark:3.4.0"}]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/", "apache/spark"]
        }
    }
    results := violation with input as inp
    count(results) == 0
}

# Test multiple containers with mixed images
test_multiple_containers_mixed_images {
    inp := {
        "review": spark_pod_review({
            "serviceAccountName": "spark-driver-sa",
            "labels": {
                "spark-job-id": "job-123",
                "spark-role": "driver",
                "app": "spark-app"
            },
            "containers": [
                {"image": "spark/spark:3.4.0"},
                {"image": "nginx:latest"}  # This should fail
            ]
        }),
        "parameters": {
            "allowedServiceAccounts": ["spark-driver-sa"],
            "requiredLabels": ["spark-job-id", "spark-role", "app"],
            "allowedImagePatterns": ["spark/", "apache/spark"]
        }
    }
    results := violation with input as inp
    count(results) == 1
    results[0].msg == "Image not allowed for Spark pods: nginx:latest"
}

# Helper function to create Spark pod review
spark_pod_review(pod_spec) = output {
    output = {
        "object": {
            "metadata": {
                "name": "spark-pod",
                "labels": pod_spec.labels
            },
            "spec": {
                "serviceAccountName": pod_spec.serviceAccountName,
                "containers": pod_spec.containers,
                "volumes": pod_spec.volumes
            }
        }
    }
}
