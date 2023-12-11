package k8sdisallowedtags

test_input_allowed_container {
    inp := { "review": input_review(input_container_allowed), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_allowed_dual_container {
    inp := { "review": input_review(input_container_dual_allowed), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_denied_container_emtpy {
    inp := { "review": input_review(input_container_denied_empty), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_container_latest {
    inp := { "review": input_review(input_container_denied_latest), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_container_testing {
    inp := { "review": input_review(input_container_denied_testing), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_dual_container_empty_tag {
    inp := { "review": input_review(array.concat(input_container_denied_empty, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_denied_dual_container_2tags {
    inp := { "review": input_review(array.concat(input_container_denied_testing, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_denied_mixed_container_empty {
    inp := { "review": input_review(array.concat(input_container_allowed, input_container_denied_empty)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_mixed_container_latest {
    inp := { "review": input_review(array.concat(input_container_allowed, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 1
}

# init containers
test_input_allowed_container {
    inp := { "review": input_init_review(input_container_allowed), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_allowed_dual_container {
    inp := { "review": input_init_review(input_container_dual_allowed), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_denied_container_emtpy {
    inp := { "review": input_init_review(input_container_denied_empty), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_container_latest {
    inp := { "review": input_init_review(input_container_denied_latest), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_container_testing {
    inp := { "review": input_init_review(input_container_denied_testing), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_dual_container_empty_tag {
    inp := { "review": input_init_review(array.concat(input_container_denied_empty, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_denied_dual_container_2tags {
    inp := { "review": input_init_review(array.concat(input_container_denied_testing, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_denied_mixed_container_empty {
    inp := { "review": input_init_review(array.concat(input_container_allowed, input_container_denied_empty)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_mixed_container_latest {
    inp := { "review": input_init_review(array.concat(input_container_allowed, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_mixed_container_with_some_exempt_image {
    inp := { "review": input_init_review(array.concat(input_container_exempt, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"], "exemptImages": ["exempt:latest"]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_denied_dual_container_with_all_exempt_image {
    inp := { "review": input_init_review(array.concat(input_container_exempt, input_container_denied_latest)), "parameters": {"tags": ["latest", "testing"], "exemptImages": ["exempt:latest", "exempt:testing"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_allowed_dual_container_with_exempt_image {
    inp := { "review": input_init_review(input_container_exempt), "parameters": {"tags": ["latest", "testing"], "exemptImages": ["exempt:latest", "exempt:testing"]}}
    results := violation with input as inp
    count(results) == 0
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
input_container_exempt = [
{
    "name": "exempt",
    "image": "exempt:latest",
}, {
    "name": "exempt",
    "image": "exempt:testing",
}]
