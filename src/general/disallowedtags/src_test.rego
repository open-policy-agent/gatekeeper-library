package k8sdisallowedtags

test_input_allowed_container {
    input := { "review": input_review(input_container_allowed), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 0
}
test_input_allowed_dual_container {
    input := { "review": input_review(input_container_dual_allowed), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 0
}
test_input_denied_container_emtpy {
    input := { "review": input_review(input_container_denied_empty), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_container_latest {
    input := { "review": input_review(input_container_denied_latest), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_container_testing {
    input := { "review": input_review(input_container_denied_testing), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_dual_container_empty_tag {
    input := { "review": input_review(array.concat(input_container_denied_empty, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 2
}
test_input_denied_dual_container_2tags {
    input := { "review": input_review(array.concat(input_container_denied_testing, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 2
}
test_input_denied_mixed_container_empty {
    input := { "review": input_review(array.concat(input_container_allowed, input_container_denied_empty)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_mixed_container_latest {
    input := { "review": input_review(array.concat(input_container_allowed, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 1
}

# init containers
test_input_allowed_container {
    input := { "review": input_init_review(input_container_allowed), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 0
}
test_input_allowed_dual_container {
    input := { "review": input_init_review(input_container_dual_allowed), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 0
}
test_input_denied_container_emtpy {
    input := { "review": input_init_review(input_container_denied_empty), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_container_latest {
    input := { "review": input_init_review(input_container_denied_latest), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_container_testing {
    input := { "review": input_init_review(input_container_denied_testing), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_dual_container_empty_tag {
    input := { "review": input_init_review(array.concat(input_container_denied_empty, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 2
}
test_input_denied_dual_container_2tags {
    input := { "review": input_init_review(array.concat(input_container_denied_testing, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 2
}
test_input_denied_mixed_container_empty {
    input := { "review": input_init_review(array.concat(input_container_allowed, input_container_denied_empty)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as input
    count(results) == 1
}
test_input_denied_mixed_container_latest {
    input := { "review": input_init_review(array.concat(input_container_allowed, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
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

input_container_allowed = [
{
    "name": "nginx",
    "image": "nginx:1.0.0",
}]

input_container_denied_empty = [
{
    "name": "nginx",
    "image": "nginx",
}]

input_container_denied_latest = [
{
    "name": "nginx",
    "image": "nginx:latest",
}]


input_container_denied_testing = [
{
    "name": "other",
    "image": "other:testing",
}]

input_container_dual_allowed = [
{
    "name": "nginx",
    "image": "nginx:1.0.0",
},
{
    "name": "other",
    "image": "other:2.0.0",
}]
