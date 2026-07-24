package k8spspprivileged

test_input_container_not_privileged_allowed {
    inp := { "review": input_review}
    results := violation with input as inp
    count(results) == 0
}
test_input_container_privileged_not_allowed {
    inp := { "review": input_review_priv}
    results := violation with input as inp
    count(results) > 0
}
test_input_container_many_not_privileged_allowed {
    inp := { "review": input_review_many}
    results := violation with input as inp
    count(results) == 0
}
test_input_container_many_mixed_privileged_not_allowed {
    inp := { "review": input_review_many_mixed}
    results := violation with input as inp
    count(results) > 0
}
test_input_container_many_mixed_privileged_not_allowed_three {
    inp := { "review": input_review_many_mixed_two}
    results := violation with input as inp
    count(results) == 2
}
test_input_container_many_mixed_privileged_not_allowed_three_but_exempt {
    inp := { "review": input_review_many_mixed_two, "parameters": {"exemptImages": ["nginx"]}}
    results := violation with input as inp
    count(results) == 0
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
            "containers": input_containers_one_priv
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
    "image": "nginx",
    "securityContext": {
      "privileged": false
    }
}]

input_containers_one_priv = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
      "privileged": true
    }
}]

input_containers_many = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
      "privileged": false
    }
},
{
    "name": "nginx1",
    "image": "nginx"
}]

input_containers_many_mixed = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
      "privileged": false
    }
},
{
    "name": "nginx1",
    "image": "nginx",
    "securityContext": {
      "privileged": true
    }
},
{
    "name": "nginx2",
    "image": "nginx",
    "securityContext": {
    }
}]
