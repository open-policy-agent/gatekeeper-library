package k8spsphostprocess

test_input_container_not_host_process_allowed {
    inp := { "review": input_review}
    results := violation with input as inp
    count(results) == 0
}

test_input_container_host_process_not_allowed {
    inp := { "review": input_review_host_process}
    results := violation with input as inp
    count(results) > 0
}

test_input_pod_host_process_not_allowed {
    inp := { "review": input_review_pod_host_process}
    results := violation with input as inp
    count(results) > 0
}

test_input_container_many_not_host_process_allowed {
    inp := { "review": input_review_many}
    results := violation with input as inp
    count(results) == 0
}

test_input_container_many_mixed_host_process_not_allowed {
    inp := { "review": input_review_many_mixed}
    results := violation with input as inp
    count(results) > 0
}

test_input_init_container_host_process_not_allowed {
    inp := { "review": input_review_init_host_process}
    results := violation with input as inp
    count(results) > 0
}

test_input_ephemeral_container_host_process_not_allowed {
    inp := { "review": input_review_ephemeral_host_process}
    results := violation with input as inp
    count(results) > 0
}

test_update {
    inp := { "review": object.union(input_review_host_process, {"operation": "UPDATE"})}
    results := violation with input as inp
    count(results) == 0
}

test_exempted_image {
    inp := { "review": input_review_host_process_exempt, "parameters": {"exemptImages": ["safeimages.com/*"]}}
    results := violation with input as inp
    count(results) == 0
}

# Test that pod-level hostProcess violation is NOT bypassed by exempt container images
test_pod_level_host_process_not_bypassed_by_exempt_container {
    inp := { "review": input_review_pod_host_process_with_exempt_container, "parameters": {"exemptImages": ["safeimages.com/*"]}}
    results := violation with input as inp
    count(results) > 0
}

input_review = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one
        }
    }
}

input_review_host_process = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one_host_process
        }
    }
}

input_review_pod_host_process = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "securityContext": {
                "windowsOptions": {
                    "hostProcess": true
                }
            },
            "containers": input_containers_one
        }
    }
}

input_review_many = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_many,
            "initContainers": input_containers_one
        }
    }
}

input_review_many_mixed = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_many,
            "initContainers": input_containers_one_host_process
        }
    }
}

input_review_init_host_process = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one,
            "initContainers": input_containers_one_host_process
        }
    }
}

input_review_ephemeral_host_process = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one,
            "ephemeralContainers": input_containers_one_host_process
        }
    }
}

input_review_host_process_exempt = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one_host_process_exempt
        }
    }
}

input_containers_one = [
{
    "name": "nginx",
    "image": "nginx"
}]

input_containers_one_host_process = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
        "windowsOptions": {
            "hostProcess": true
        }
    }
}]

input_containers_one_host_process_exempt = [
{
    "name": "nginx",
    "image": "safeimages.com/nginx",
    "securityContext": {
        "windowsOptions": {
            "hostProcess": true
        }
    }
}]

input_containers_many = [
{
    "name": "nginx",
    "image": "nginx"
},
{
    "name": "nginx1",
    "image": "nginx"
}]

# Pod-level hostProcess with exempt container image - should still violate
input_review_pod_host_process_with_exempt_container = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "securityContext": {
                "windowsOptions": {
                    "hostProcess": true
                }
            },
            "containers": [{
                "name": "nginx",
                "image": "safeimages.com/nginx"
            }]
        }
    }
}
