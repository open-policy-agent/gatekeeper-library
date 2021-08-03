package k8spspprivileged


violation[{"msg": msg, "details": {}}] {
    c := input_containers[_]
    input_allow_privileged_container(c)
    msg := sprintf("Privileged container is not allowed: %v", [c.name])
}

input_allow_privileged_container(c) {
    not has_field(c, "securityContext")
}

input_allow_privileged_container(c) {
    not c.securityContext.privileged == false
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}

input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}

# has_field returns whether an object has a field
has_field(object, field) = true {
    object[field]
}