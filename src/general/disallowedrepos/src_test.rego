package k8sdisallowedrepos

test_input_allowed_container {
    input := { "review": input_review(input_container_disallowed), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as input
    count(results) == 0
}
test_input_allowed_container_x2 {
    input := { "review": input_review(input_container_disallowed), "parameters": {"repos": ["other", "disallowed"]}}
    results := violation with input as input
    count(results) == 0
}
test_input_allowed_dual_container {
    input := { "review": input_review(input_container_dual_disallowed), "parameters": {"repos": ["allowed"]}}
    results := violation with input as input
    count(results) == 0
}
test_input_denied_container {
    input := { "review": input_review(input_container_denied), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_container_x2 {
    input := { "review": input_review(input_container_denied), "parameters": {"repos": ["other", "disallowed"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_dual_container {
    input := { "review": input_review(input_container_dual_denied), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as input
    count(results) == 2
}
test_input_denied_mixed_container {
    input := { "review": input_review(array.concat(input_container_disallowed, input_container_denied)), "parameters": {"repos": ["allowed"]}}
    results := violation with input as input
    count(results) == 1
}

# init containers
test_input_allowed_initcontainer {
    input := { "review": input_init_review(input_container_disallowed), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as input
    count(results) == 0
}
test_input_allowed_initcontainer_x2 {
    input := { "review": input_init_review(input_container_disallowed), "parameters": {"repos": ["other", "disallowed"]}}
    results := violation with input as input
    count(results) == 0
}
test_input_allowed_dual_initcontainer {
    input := { "review": input_init_review(input_container_dual_disallowed), "parameters": {"repos": ["allowed"]}}
    results := violation with input as input
    count(results) == 0
}
test_input_denied_initcontainer {
    input := { "review": input_init_review(input_container_denied), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_initcontainer_x2 {
    input := { "review": input_init_review(input_container_denied), "parameters": {"repos": ["other", "disallowed"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_dual_initcontainer {
    input := { "review": input_init_review(input_container_dual_denied), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as input
    count(results) == 2
}
test_input_denied_mixed_initcontainer {
    input := { "review": input_init_review(array.concat(input_container_disallowed, input_container_denied)), "parameters": {"repos": ["allowed"]}}
    results := violation with input as input
    count(results) == 1
}

input_review(containers) = output {
    output = {
      "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": containers,
        }
      }
     }
}

input_init_review(containers) = output {
    output = {
      "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "initContainers": containers,
        }
      }
     }
}

input_container_disallowed = [
{
    "name": "nginx",
    "image": "allowed/nginx",
}]

input_container_denied = [
{
    "name": "nginx",
    "image": "disallowed/nginx",
}]

input_container_dual_disallowed = [
{
    "name": "nginx",
    "image": "disallowed/nginx",
},
{
    "name": "other",
    "image": "disallowed/other",
}]

input_container_dual_denied = [
{
    "name": "nginx",
    "image": "disallowed/nginx",
},
{
    "name": "other",
    "image": "disallowed/other",
}]
