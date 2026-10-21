package k8snounsupportedgpu

test_gpu_with_env_var_allowed {
    inp := {
        "review": review([gpu_container_with_env("training", "nvidia/cuda:12.0", "1")]),
        "parameters": {},
    }
    results := violation with input as inp
    count(results) == 0
}

test_no_gpu_requested_allowed {
    inp := {
        "review": review([no_gpu_container("web", "nginx:latest")]),
        "parameters": {},
    }
    results := violation with input as inp
    count(results) == 0
}

test_gpu_without_env_var_denied {
    inp := {
        "review": review([gpu_container_no_env("training", "myrepo/myimage:v1", "1")]),
        "parameters": {},
    }
    results := violation with input as inp
    count(results) == 1
}

test_gpu_without_env_var_multiple_denied {
    inp := {
        "review": review([
            gpu_container_no_env("training1", "myrepo/myimage:v1", "1"),
            gpu_container_no_env("training2", "myrepo/myimage:v2", "2"),
        ]),
        "parameters": {},
    }
    results := violation with input as inp
    count(results) == 2
}

test_gpu_zero_allowed {
    inp := {
        "review": review([gpu_container_no_env_zero("training", "myrepo/myimage:v1")]),
        "parameters": {},
    }
    results := violation with input as inp
    count(results) == 0
}

test_mixed_containers {
    inp := {
        "review": review([
            gpu_container_with_env("good", "nvidia/cuda:12.0", "1"),
            gpu_container_no_env("bad", "myrepo/myimage:v1", "1"),
            no_gpu_container("web", "nginx:latest"),
        ]),
        "parameters": {},
    }
    results := violation with input as inp
    count(results) == 1
}

test_exempt_image {
    inp := {
        "review": review([gpu_container_no_env("training", "exempt-registry/myimage:v1", "1")]),
        "parameters": {"exemptImages": ["exempt-registry/*"]},
    }
    results := violation with input as inp
    count(results) == 0
}

test_init_container_gpu_denied {
    inp := {
        "review": review_with_init(
            [no_gpu_container("web", "nginx:latest")],
            [gpu_container_no_env("init-gpu", "myrepo/init:v1", "1")],
        ),
        "parameters": {},
    }
    results := violation with input as inp
    count(results) == 1
}

# Helper functions
review(containers) = output {
    output = {
        "object": {
            "metadata": {
                "name": "test-pod",
            },
            "spec": {
                "containers": containers,
            },
        },
    }
}

review_with_init(containers, init_containers) = output {
    output = {
        "object": {
            "metadata": {
                "name": "test-pod",
            },
            "spec": {
                "containers": containers,
                "initContainers": init_containers,
            },
        },
    }
}

gpu_container_with_env(name, image, gpus) = c {
    c := {
        "name": name,
        "image": image,
        "resources": {
            "limits": {
                "nvidia.com/gpu": gpus,
            },
        },
        "env": [
            {"name": "NVIDIA_VISIBLE_DEVICES", "value": "all"},
        ],
    }
}

gpu_container_no_env(name, image, gpus) = c {
    c := {
        "name": name,
        "image": image,
        "resources": {
            "limits": {
                "nvidia.com/gpu": gpus,
            },
        },
    }
}

gpu_container_no_env_zero(name, image) = c {
    c := {
        "name": name,
        "image": image,
        "resources": {
            "limits": {
                "nvidia.com/gpu": "0",
            },
        },
    }
}

no_gpu_container(name, image) = c {
    c := {
        "name": name,
        "image": image,
        "resources": {
            "limits": {
                "cpu": "100m",
                "memory": "128Mi",
            },
        },
    }
}
