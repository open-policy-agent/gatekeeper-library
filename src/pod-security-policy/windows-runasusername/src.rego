package windowsrunasusername

violation[{"msg": msg}] {
    isWindowsPod
    container := input_containers[_]
    has_disallowed_username(container)
    msg := sprintf("Container <%v> has disallowed runAsUsername. Disallowed users are %v", [container.name, input.parameters.disallowedUserNames])
}

has_disallowed_username(c) {
    un := get_username(c)
    input.parameters.disallowedUserNames[_] == un
}

# returns runAsUserName if set for container
get_username(c) = out {
    un := c.securityContext.windowsOptions.runAsUserName
    out = un
}

# returns runAsUserName if NOT set for container but IS set for pod
get_username(c) = out {
    not has_username_set_for_container(c)
    un := input.review.object.spec.securityContext.windowsOptions.runAsUserName
    out = un
}

has_username_set_for_container(c) {
    c.securityContext.windowsOptions.runAsUserName
}

isWindowsPod {
    ns := input.review.object.spec.nodeSelector
    ns["kubernetes.io/os"] == "windows"
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}

input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}