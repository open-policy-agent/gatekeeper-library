package k8sdisallowedrepos

test_input_allowed_container {
    inp := { "review": input_review(input_container_allowed), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_allowed_container_x2 {
    inp := { "review": input_review(input_container_allowed), "parameters": {"repos": ["other", "disallowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_allowed_dual_container {
    inp := { "review": input_review(input_container_dual_allowed), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_denied_container {
    inp := { "review": input_review(input_container_denied), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_container_x2 {
    inp := { "review": input_review(input_container_denied), "parameters": {"repos": ["other", "disallowed"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_dual_container {
    inp := { "review": input_review(input_container_dual_denied), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_denied_mixed_container {
    inp := { "review": input_review(array.concat(input_container_allowed, input_container_denied)), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as inp
    count(results) == 1
}

# init containers
test_input_allowed_initcontainer {
    inp := { "review": input_init_review(input_container_allowed), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_allowed_initcontainer_x2 {
    inp := { "review": input_init_review(input_container_allowed), "parameters": {"repos": ["other", "disallowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_allowed_dual_initcontainer {
    inp := { "review": input_init_review(input_container_dual_allowed), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_denied_initcontainer {
    inp := { "review": input_init_review(input_container_denied), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_initcontainer_x2 {
    inp := { "review": input_init_review(input_container_denied), "parameters": {"repos": ["other", "disallowed"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_dual_initcontainer {
    inp := { "review": input_init_review(input_container_dual_denied), "parameters": {"repos": ["disallowed"]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_denied_mixed_initcontainer {
    inp := { "review": input_init_review(array.concat(input_container_allowed, input_container_denied)), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
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

input_container_allowed = [
{
    "name": "nginx",
    "image": "allowed/nginx",
}]

input_container_denied = [
{
    "name": "nginx",
    "image": "disallowed/nginx",
}]

input_container_dual_allowed = [
{
    "name": "nginx",
    "image": "allowed/nginx",
},
{
    "name": "other",
    "image": "allowed/other",
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
