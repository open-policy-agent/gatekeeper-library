package k8spspallowprivilegeescalationcontainer

test_input_container_not_privilege_escalation_allowed {
    inp := { "review": input_review}
    results := violation with input as inp
    count(results) == 0
}
test_input_container_privilege_escalation_not_allowed {
    inp := { "review": input_review_priv}
    results := violation with input as inp
    count(results) == 1
}
test_input_one_container_with_exemption {
    inp := { "review": input_review_priv, "parameters": {"exemptImages": ["one/*"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_container_many_not_privilege_escalation_allowed {
    inp := { "review": input_review_many}
    results := violation with input as inp
    count(results) == 2
}
test_input_container_many_mixed_privilege_escalation_not_allowed {
    inp := { "review": input_review_many_mixed}
    results := violation with input as inp
    count(results) == 3
}
test_input_container_many_mixed_privilege_escalation_not_allowed_one_exempted {
    inp := { "review": input_review_many_mixed, "parameters": {"exemptImages": ["one/*"]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_container_many_mixed_privilege_escalation_not_allowed_all_exempted {
    inp := { "review": input_review_many_mixed, "parameters": {"exemptImages": ["one/*", "two/*", "three/*"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_container_many_mixed_privilege_escalation_not_allowed_two {
    inp := { "review": input_review_many_mixed_two}
    results := violation with input as inp
    count(results) == 2
}
test_update {
    inp := { "review": object.union(input_review_priv, {"operation": "UPDATE"})}
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

input_review_priv = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one_priv,
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
            "initContainers": input_containers_one_priv
      }
    }
}

input_review_many_mixed_two = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_many_mixed,
            "initContainers": input_containers_one_priv
      }
    }
}

input_containers_one = [
{
    "name": "nginx",
    "image": "one/nginx",
    "securityContext": {
      "allowPrivilegeEscalation": false
    }
}]

input_containers_one_priv = [
{
    "name": "nginx",
    "image": "one/nginx",
    "securityContext": {
      "allowPrivilegeEscalation": true
    }
}]

input_containers_many = [
{
    "name": "nginx",
    "image": "one/nginx",
    "securityContext": {
      "allowPrivilegeEscalation": false
    }
},
{
    "name": "nginx1",
    "image": "two/nginx"
},
{
    "name": "nginx2",
    "image": "three/nginx",
    "securityContext": {
      "runAsUser": "1000"
    }

}]

input_containers_many_mixed = [
{
    "name": "nginx",
    "image": "one/nginx",
    "securityContext": {
      "allowPrivilegeEscalation": false
    }
},
{
    "name": "nginx1",
    "image": "two/nginx",
    "securityContext": {
      "allowPrivilegeEscalation": true
    }
}]
