package k8sdisallowinteractivetty

test_input_container_not_tty_allowed {
    inp := {"review": input_review}
    results := violation with input as inp
    count(results) == 0
}
test_input_container_stdin_not_allowed {
    inp:= {"review": input_review_stdin}
    results := violation with input as inp
    count(results) == 1
}
test_input_container_tty_not_allowed {
    inp := {"review": input_review_tty}
    results := violation with input as inp
    count(results) == 1
}
test_input_one_container_with_exemption {
    inp := {"review": input_review_stdin, "parameters": {"exemptImages": ["one/*"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_container_many_not_stdin_allowed {
    inp := {"review": input_review_many}
    results := violation with input as inp
    count(results) == 1
}
test_input_container_many_mixed_stdin_not_allowed {
    inp := {"review": input_review_many_mixed}
    results := violation with input as inp
    count(results) == 2
}
test_input_container_many_mixed_stdin_not_allowed_one_exempted {
    inp := {"review": input_review_many_mixed, "parameters": {"exemptImages": ["one/*"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_container_many_mixed_stdin_not_allowed_all_exempted {
    inp := {"review": input_review_many_mixed, "parameters": {"exemptImages": ["one/*", "two/*", "three/*"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_container_many_mixed_stdin_not_allowed_two {
    inp := {"review": input_review_many_mixed_two}
    results := violation with input as inp
    count(results) == 2
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

input_review_stdin = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one_stdin,
      }
    }
}

input_review_tty = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one_tty,
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
            "initContainers": input_containers_one_stdin
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
            "initContainers": input_containers_one_stdin
      }
    }
}

input_containers_one = [
{
    "name": "nginx",
    "image": "one/nginx",
}]

input_containers_one_stdin = [
{
    "name": "nginx",
    "image": "one/nginx",
    "stdin": true
}]

input_containers_one_tty = [
{
    "name": "nginx",
    "image": "one/nginx",
    "tty": true
}]

input_containers_many = [
{
    "name": "nginx",
    "image": "one/nginx",
    "stdin": false
},
{
    "name": "nginx1",
    "image": "two/nginx"
},
{
    "name": "nginx2",
    "image": "three/nginx",
    "stdin": true

}]

input_containers_many_mixed = [
{
    "name": "nginx",
    "image": "one/nginx",
    "stdin": false
},
{
    "name": "nginx1",
    "image": "two/nginx",
    "tty": true
}]
