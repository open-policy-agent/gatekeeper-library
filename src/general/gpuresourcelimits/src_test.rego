package k8sgpuresourcelimits

test_gpu_within_limit_allowed {
    inp := {"review": review([gpu_container("training", "nvidia/cuda:12.0", "2")]), "parameters": {"maxGpuPerContainer": 4}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_exceeds_limit_denied {
    inp := {"review": review([gpu_container("training", "nvidia/cuda:12.0", "8")]), "parameters": {"maxGpuPerContainer": 4}}
    results := violation with input as inp
    count(results) == 1
}

test_no_gpu_allowed {
    inp := {"review": review([no_gpu_container("web", "nginx:latest")]), "parameters": {"maxGpuPerContainer": 4}}
    results := violation with input as inp
    count(results) == 0
}

test_exempt_image_allowed {
    inp := {"review": review([gpu_container("monitor", "nvidia/dcgm-exporter:3.1", "8")]), "parameters": {"maxGpuPerContainer": 4, "exemptImages": ["nvidia/dcgm-exporter:*"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_containers_mixed {
    inp := {"review": review([gpu_container("ok", "nvidia/cuda:12.0", "2"), gpu_container("bad", "myrepo/train:v1", "8")]), "parameters": {"maxGpuPerContainer": 4}}
    results := violation with input as inp
    count(results) == 1
}

test_zero_gpu_allowed {
    inp := {"review": review([gpu_container("idle", "myrepo/train:v1", "0")]), "parameters": {"maxGpuPerContainer": 4}}
    results := violation with input as inp
    count(results) == 0
}

review(containers) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers}}}
}

gpu_container(name, image, gpus) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"nvidia.com/gpu": gpus}}}
}

no_gpu_container(name, image) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}}
}
