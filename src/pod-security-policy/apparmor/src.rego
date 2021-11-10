package k8spspapparmor

violation[{"msg": msg, "details": {}}] {
    metadata := input.review.object.metadata
    container := input_containers[_]
    not input_apparmor_allowed(container, metadata)
    msg := sprintf("AppArmor profile is not allowed, pod: %v, container: %v. Allowed profiles: %v", [input.review.object.metadata.name, container.name, input.parameters.allowedProfiles])
}

input_apparmor_allowed(container, metadata) {
    get_annotation_for(container, metadata) == input.parameters.allowedProfiles[_]
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}

get_annotation_for(container, metadata) = out {
    out = metadata.annotations[sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])]
}
get_annotation_for(container, metadata) = out {
    not metadata.annotations[sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])]
    out = "runtime/default"
}
