package k8sdisallowedtags

import data.lib.exempt_container.is_exempt

violation[{"msg": msg}] {
    container := input_containers[_]
    not is_exempt(container)
    tags := [forbid | tag = input.parameters.tags[_] ; forbid = endswith(container.image, concat(":", ["", tag]))]
    any(tags)
    msg := sprintf("container <%v> uses a disallowed tag <%v>; disallowed tags are %v", [container.name, container.image, input.parameters.tags])
}

violation[{"msg": msg}] {
    container := input_containers[_]
    not is_exempt(container)
    tag := [contains(container.image, ":")]
    not all(tag)
    msg := sprintf("container <%v> didn't specify an image tag <%v>", [container.name, container.image])
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
input_containers[c] {
    c := input.review.object.spec.ephemeralContainers[_]
}
