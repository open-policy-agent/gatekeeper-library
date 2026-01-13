package k8spsphostprobeslifecycle

test_input_container_no_probes_allowed {
    inp := { "review": input_review}
    results := violation with input as inp
    count(results) == 0
}

test_input_container_probe_without_host_allowed {
    inp := { "review": input_review_probe_no_host}
    results := violation with input as inp
    count(results) == 0
}

test_input_container_probe_with_host_not_allowed {
    inp := { "review": input_review_probe_with_host}
    results := violation with input as inp
    count(results) > 0
}

test_input_container_lifecycle_with_host_not_allowed {
    inp := { "review": input_review_lifecycle_with_host}
    results := violation with input as inp
    count(results) > 0
}

test_input_container_readiness_probe_with_host_not_allowed {
    inp := { "review": input_review_readiness_probe_with_host}
    results := violation with input as inp
    count(results) > 0
}

test_input_container_startup_probe_with_host_not_allowed {
    inp := { "review": input_review_startup_probe_with_host}
    results := violation with input as inp
    count(results) > 0
}

test_input_container_prestop_with_host_not_allowed {
    inp := { "review": input_review_prestop_with_host}
    results := violation with input as inp
    count(results) > 0
}

test_input_container_tcp_probe_with_host_not_allowed {
    inp := { "review": input_review_tcp_probe_with_host}
    results := violation with input as inp
    count(results) > 0
}

test_update {
    inp := { "review": object.union(input_review_probe_with_host, {"operation": "UPDATE"})}
    results := violation with input as inp
    count(results) == 0
}

test_exempted_image {
    inp := { "review": input_review_probe_with_host_exempt, "parameters": {"exemptImages": ["safeimages.com/*"]}}
    results := violation with input as inp
    count(results) == 0
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

input_review_probe_no_host = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_probe_no_host
        }
    }
}

input_review_probe_with_host = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_probe_with_host
        }
    }
}

input_review_lifecycle_with_host = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_lifecycle_with_host
        }
    }
}

input_review_readiness_probe_with_host = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_readiness_probe_with_host
        }
    }
}

input_review_startup_probe_with_host = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_startup_probe_with_host
        }
    }
}

input_review_prestop_with_host = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_prestop_with_host
        }
    }
}

input_review_tcp_probe_with_host = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_tcp_probe_with_host
        }
    }
}

input_review_probe_with_host_exempt = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_probe_with_host_exempt
        }
    }
}

input_containers_one = [
{
    "name": "nginx",
    "image": "nginx"
}]

input_containers_probe_no_host = [
{
    "name": "nginx",
    "image": "nginx",
    "livenessProbe": {
        "httpGet": {
            "path": "/",
            "port": 80
        }
    }
}]

input_containers_probe_with_host = [
{
    "name": "nginx",
    "image": "nginx",
    "livenessProbe": {
        "httpGet": {
            "path": "/",
            "port": 80,
            "host": "127.0.0.1"
        }
    }
}]

input_containers_lifecycle_with_host = [
{
    "name": "nginx",
    "image": "nginx",
    "lifecycle": {
        "postStart": {
            "httpGet": {
                "path": "/",
                "port": 80,
                "host": "127.0.0.1"
            }
        }
    }
}]

input_containers_readiness_probe_with_host = [
{
    "name": "nginx",
    "image": "nginx",
    "readinessProbe": {
        "httpGet": {
            "path": "/",
            "port": 80,
            "host": "127.0.0.1"
        }
    }
}]

input_containers_startup_probe_with_host = [
{
    "name": "nginx",
    "image": "nginx",
    "startupProbe": {
        "httpGet": {
            "path": "/",
            "port": 80,
            "host": "127.0.0.1"
        }
    }
}]

input_containers_prestop_with_host = [
{
    "name": "nginx",
    "image": "nginx",
    "lifecycle": {
        "preStop": {
            "httpGet": {
                "path": "/",
                "port": 80,
                "host": "127.0.0.1"
            }
        }
    }
}]

input_containers_tcp_probe_with_host = [
{
    "name": "nginx",
    "image": "nginx",
    "livenessProbe": {
        "tcpSocket": {
            "port": 80,
            "host": "127.0.0.1"
        }
    }
}]

input_containers_probe_with_host_exempt = [
{
    "name": "nginx",
    "image": "safeimages.com/nginx",
    "livenessProbe": {
        "httpGet": {
            "path": "/",
            "port": 80,
            "host": "127.0.0.1"
        }
    }
}]
