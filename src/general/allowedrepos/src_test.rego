package k8sallowedreposv2

test_input_allowed_container {
    inp := { "review": input_review(input_container_allowed), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_allowed_container_x2 {
    inp := { "review": input_review(input_container_allowed), "parameters": {"repos": ["other", "allowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_allowed_dual_container {
    inp := { "review": input_review(input_container_dual_allowed), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_denied_container {
    inp := { "review": input_review(input_container_denied), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_container_x2 {
    inp := { "review": input_review(input_container_denied), "parameters": {"repos": ["other", "allowed"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_dual_container {
    inp := { "review": input_review(input_container_dual_denied), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_denied_mixed_container {
    inp := { "review": input_review(array.concat(input_container_allowed, input_container_denied)), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
    count(results) == 1
}

# init containers
test_input_allowed_container {
    inp := { "review": input_init_review(input_container_allowed), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_allowed_container_x2 {
    inp := { "review": input_init_review(input_container_allowed), "parameters": {"repos": ["other", "allowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_allowed_dual_container {
    inp := { "review": input_init_review(input_container_dual_allowed), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_denied_container {
    inp := { "review": input_init_review(input_container_denied), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_container_x2 {
    inp := { "review": input_init_review(input_container_denied), "parameters": {"repos": ["other", "allowed"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_denied_dual_container {
    inp := { "review": input_init_review(input_container_dual_denied), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_denied_mixed_container {
    inp := { "review": input_init_review(array.concat(input_container_allowed, input_container_denied)), "parameters": {"repos": ["allowed"]}}
    results := violation with input as inp
    count(results) == 1
}

test_input_bypass_registry_mixed_container {
    inp := { "review": input_init_review(array.concat(input_container_registry_bypass_denied, input_container_registry_bypass_allowed)), "parameters": {"repos": ["myregistry.azurecr.io"]}}
    results := violation with input as inp
    count(results) == 1
}

test_input_bypass_repository_mixed_container {
    inp := { "review": input_init_review(array.concat(input_container_repository_bypass_denied, input_container_repository_bypass_allowed)), "parameters": {"repos": ["mydockerhub"]}}
    results := violation with input as inp
    count(results) == 1
}

test_input_bypass_images_mixed_container {
    inp := { "review": input_init_review(array.concat(input_container_image_bypass_dual_denied, input_container_image_bypass_dual_allowed)), "parameters": {"images": ["ubuntu","123456789123.dkr.ecr.eu-west-1.amazonaws.com/postgres"]}}
    results := violation with input as inp
    count(results) == 2
}

test_input_images_and_repo_allowed {
    inp := { "review": input_init_review(array.concat(input_container_dual_allowed,input_container_image_bypass_dual_allowed)), "parameters": {"repos": ["allowed"],"images": ["ubuntu","123456789123.dkr.ecr.eu-west-1.amazonaws.com/postgres"]}}
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
    "image": "allowed/nginx",
}]

input_container_denied = [
{
    "name": "nginx",
    "image": "denied/nginx",
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
    "image": "denied/nginx",
},
{
    "name": "other",
    "image": "denied/other",
}]

input_container_registry_bypass_denied = [
{
    "name": "postgress",
    "image": "myregistry.azurecr.io.malicious.com/postgress",
}]

input_container_registry_bypass_allowed = [
{
    "name": "postgress",
    "image": "myregistry.azurecr.io/postgress",
}]

input_container_repository_bypass_denied = [
{
    "name": "python",
    "image": "mydockerhubmalicious/python",
}]

input_container_repository_bypass_allowed = [
{
    "name": "python",
    "image": "mydockerhub/python",
}]

input_container_image_bypass_dual_denied = [
{
    "name": "ubuntumalicious",
    "image": "ubuntumalicious:20.04",
},
{
    "name": "postgresmalicious",
    "image": "123456789123.dkr.ecr.eu-west-1.amazonaws.com/postgresmalicious",
}]

input_container_image_bypass_dual_allowed = [
{
    "name": "ubuntu",
    "image": "ubuntu@sha256:26c68657ccce2cb0a31b330cb0be2b5e108d467f641c62e13ab40cbec258c68d",
},
{
    "name": "postgres",
    "image": "123456789123.dkr.ecr.eu-west-1.amazonaws.com/postgres:latest",
}]
