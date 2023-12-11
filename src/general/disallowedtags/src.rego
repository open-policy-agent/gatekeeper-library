package k8sdisallowedtags

import data.lib.exempt_container.is_exempt

violation[{"msg": msg}] {
    container := input_containers[_]
    not is_exempt(container)
    tags := [tag_with_prefix | tag := input.parameters.tags[_]; tag_with_prefix := concat(":", ["", tag])]
    strings.any_suffix_match(container.image, tags)
    msg := sprintf("container <%v> uses a disallowed tag <%v>; disallowed tags are %v", [container.name, container.image, input.parameters.tags])
}

violation[{"msg": msg}] {
    container := input_containers[_]
    not is_exempt(container)
    not contains(container.image, ":")
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
