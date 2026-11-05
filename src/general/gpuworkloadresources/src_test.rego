package k8sgpuworkloadresources

test_gpu_pod_compliant_allowed {
    inp := {"review": review([compliant_gpu_container("trainer"), compliant_sidecar("logger")]), "parameters": {}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_container_missing_gpu_request_denied {
    inp := {"review": review([gpu_limit_only_container("trainer")]), "parameters": {}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_pod_memory_mismatch_denied {
    inp := {"review": review([gpu_memory_mismatch_container("trainer")]), "parameters": {}}
    results := violation with input as inp
    count(results) == 1
}

test_gpu_pod_sidecar_missing_cpu_request_denied {
    inp := {"review": review([compliant_gpu_container("trainer"), sidecar_missing_cpu_request("logger")]), "parameters": {}}
    results := violation with input as inp
    count(results) == 1
}

test_non_gpu_pod_allowed {
    inp := {"review": review([non_gpu_container("web")]), "parameters": {}}
    results := violation with input as inp
    count(results) == 0
}

test_exempt_gpu_container_allowed {
    inp := {"review": review([gpu_limit_only_container_with_image("monitor", "nvidia/dcgm-exporter:3.1")]), "parameters": {"exemptImages": ["nvidia/dcgm-exporter:*"]}}
    results := violation with input as inp
    count(results) == 0
}

review(containers) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers}}}
}

compliant_gpu_container(name) = c {
    c := {
        "name": name,
        "image": "nvidia/cuda:12.0-runtime",
        "resources": {
            "requests": {"nvidia.com/gpu": "1", "memory": "16Gi", "cpu": "2"},
            "limits": {"nvidia.com/gpu": "1", "memory": "16Gi", "cpu": "4"},
        },
    }
}

compliant_sidecar(name) = c {
    c := {
        "name": name,
        "image": "busybox:1.36",
        "resources": {
            "requests": {"memory": "256Mi", "cpu": "100m"},
            "limits": {"memory": "256Mi", "cpu": "500m"},
        },
    }
}

gpu_limit_only_container(name) = c {
    c := gpu_limit_only_container_with_image(name, "nvidia/cuda:12.0-runtime")
}

gpu_limit_only_container_with_image(name, image) = c {
    c := {
        "name": name,
        "image": image,
        "resources": {
            "requests": {"memory": "16Gi", "cpu": "2"},
            "limits": {"nvidia.com/gpu": "1", "memory": "16Gi", "cpu": "4"},
        },
    }
}

gpu_memory_mismatch_container(name) = c {
    c := {
        "name": name,
        "image": "nvidia/cuda:12.0-runtime",
        "resources": {
            "requests": {"nvidia.com/gpu": "1", "memory": "8Gi", "cpu": "2"},
            "limits": {"nvidia.com/gpu": "1", "memory": "16Gi", "cpu": "4"},
        },
    }
}

sidecar_missing_cpu_request(name) = c {
    c := {
        "name": name,
        "image": "busybox:1.36",
        "resources": {
            "requests": {"memory": "256Mi"},
            "limits": {"memory": "256Mi", "cpu": "500m"},
        },
    }
}

non_gpu_container(name) = c {
    c := {
        "name": name,
        "image": "nginx:1.25",
        "resources": {
            "requests": {"memory": "128Mi", "cpu": "100m"},
            "limits": {"memory": "256Mi", "cpu": "500m"},
        },
    }
}