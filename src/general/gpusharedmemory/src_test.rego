package k8sgpusharedmemory

test_gpu_with_shm_allowed {
    inp := {"review": review_with_shm([gpu_container_with_shm("train", "nvidia/cuda:12.0", "1")]), "parameters": {}}
    results := violation with input as inp
    count(results) == 0
}

test_gpu_without_shm_denied {
    inp := {"review": review([gpu_container("train", "nvidia/cuda:12.0", "1")]), "parameters": {}}
    results := violation with input as inp
    count(results) == 1
}

test_no_gpu_allowed {
    inp := {"review": review([no_gpu_container("web", "nginx:latest")]), "parameters": {}}
    results := violation with input as inp
    count(results) == 0
}

review(containers) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers}}}
}

review_with_shm(containers) = output {
    output = {"object": {"metadata": {"name": "test-pod"}, "spec": {"containers": containers, "volumes": [{"name": "dshm", "emptyDir": {"medium": "Memory"}}]}}}
}

gpu_container(name, image, gpus) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"nvidia.com/gpu": gpus}}}
}

gpu_container_with_shm(name, image, gpus) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"nvidia.com/gpu": gpus}}, "volumeMounts": [{"name": "dshm", "mountPath": "/dev/shm"}]}
}

no_gpu_container(name, image) = c {
    c := {"name": name, "image": image, "resources": {"limits": {"cpu": "100m"}}}
}
