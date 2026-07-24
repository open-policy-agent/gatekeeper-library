package k8spspreadonlyrootfilesystem

test_input_container_not_readonlyrootfilesystem_allowed {
    inp := { "review": input_review}
    results := violation with input as inp
    count(results) == 1
}
test_input_container_readonlyrootfilesystem_not_allowed {
    inp := { "review": input_review_ro}
    results := violation with input as inp
    count(results) == 0
}
test_input_container_many_mixed_readonlyrootfilesystem_not_allowed {
    inp := { "review": input_review_many_mixed}
    results := violation with input as inp
    count(results) == 2
}
test_input_container_many_mixed_readonlyrootfilesystem_not_allowed_two {
    inp := { "review": input_review_many_mixed_two}
    results := violation with input as inp
    count(results) == 3
}
test_input_container_many_mixed_readonlyrootfilesystem_not_allowed_two_but_exempt {
    inp := { "review": input_review_many_mixed_two, "parameters": {"exemptImages": ["nginx"]} }
    results := violation with input as inp
    count(results) == 0
}
test_update {
    inp := { "review": object.union(input_review, {"operation": "UPDATE"})}
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

input_review_ro = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one_ro
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
            "initContainers": input_containers_one
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
            "initContainers": input_containers_one_ro
      }
    }
}

input_containers_one = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
      "readOnlyRootFilesystem": false
    }
}]

input_containers_one_ro = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
      "readOnlyRootFilesystem": true
    }
}]

input_containers_many = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
      "readOnlyRootFilesystem": true
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
      "readOnlyRootFilesystem": false
    }
},
{
    "name": "nginx1",
    "image": "nginx",
    "securityContext": {
      "readOnlyRootFilesystem": true
    }
},
{
    "name": "nginx2",
    "image": "nginx"
},
{
    "name": "nginx3",
    "image": "nginx",
    "securityContext": {
      "runAsUser": "1000"
    }
}]
