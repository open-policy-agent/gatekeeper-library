package k8sautomountserviceaccounttoken

test_input_pod_not_automountserviceaccounttoken_allowed {
    inp := {"review": input_review_disabled_automountserviceaccounttoken}
    results := violation with input as inp
    count(results) == 0
}

test_input_pod_automountserviceaccounttoken_not_allowed {
    inp := {"review": input_review_enabled_automountserviceaccounttoken}
    results := violation with input as inp
    count(results) > 0
}

test_input_pod_automountserviceaccounttoken_not_defined {
    inp := {"review": input_review_no_automountserviceaccounttoken_defined_and_enabled_volumemount}
    results := violation with input as inp
    count(results) > 0
}

test_update {
    inp := {"review": object.union(input_review_enabled_automountserviceaccounttoken, {"operation": "UPDATE"})}
    results := violation with input as inp
    count(results) == 0
}

input_review_disabled_automountserviceaccounttoken = {"object": {
    "metadata": {"name": "nginx"},
    "spec": {
        "automountServiceAccountToken": false,
        "containers": input_containers_one,
    },
}}

input_review_enabled_automountserviceaccounttoken = {"object": {
    "metadata": {"name": "nginx"},
    "spec": {
        "automountServiceAccountToken": true,
        "containers": input_containers_one,
    },
}}

input_review_no_automountserviceaccounttoken_defined_and_enabled_volumemount = {"object": {
    "metadata": {"name": "nginx"},
    "spec": {"containers": input_containers_volumemount},
}}

input_containers_one = [{
    "name": "nginx",
    "image": "nginx",
}]

input_containers_volumemount = [{
    "name": "nginx",
    "image": "nginx",
    "volumeMounts": [{
        "name": "serviceaccount-vm",
        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
    }],
}]
