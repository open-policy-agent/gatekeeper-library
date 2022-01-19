package k8sdisallowedtags

violation[{"msg": msg}] {
    container := input_containers[_]
    matched_allowed_images := [allowed | image = input.parameters.allowedImages[_]; allowed = (image == container.image) ]
    not any(matched_allowed_images)
    tags := [forbid | tag = input.parameters.tags[_] ; forbid = endswith(container.image, concat(":", ["", tag]))]
    any(tags)
    msg := sprintf("container <%v> uses a disallowed tag <%v>; disallowed tags are %v", [container.name, container.image, input.parameters.tags])
}

violation[{"msg": msg}] {
    container := input_containers[_]
    matched_allowed_images := [allowed | image = input.parameters.allowedImages[_]; allowed = (image == container.image) ]
    not any(matched_allowed_images)
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
