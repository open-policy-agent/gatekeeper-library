package k8spspprocmount

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation[{"msg": msg, "details": {}}] {
    # spec.containers.securityContext.procMount field is immutable.
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    allowedProcMount := get_allowed_proc_mount(input)
    not input_proc_mount_type_allowed(allowedProcMount, c)
    msg := sprintf("ProcMount type is not allowed, container: %v. Allowed procMount types: %v", [c.name, allowedProcMount])
}

input_proc_mount_type_allowed(allowedProcMount, c) {
    allowedProcMount == "default"
    lower(c.securityContext.procMount) == "default"
}
input_proc_mount_type_allowed(allowedProcMount, _) {
    allowedProcMount == "unmasked"
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
    c.securityContext.procMount != null
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
    c.securityContext.procMount != null
}
input_containers[c] {
    c := input.review.object.spec.ephemeralContainers[_]
    c.securityContext.procMount != null
}

get_allowed_proc_mount(arg) = out {
    not arg.parameters
    out = "default"
}
get_allowed_proc_mount(arg) = out {
    not arg.parameters.procMount
    out = "default"
}
get_allowed_proc_mount(arg) = out {
    arg.parameters.procMount
    not valid_proc_mount(arg.parameters.procMount)
    out = "default"
}
get_allowed_proc_mount(arg) = out {
    valid_proc_mount(arg.parameters.procMount)
    out = lower(arg.parameters.procMount)
}

valid_proc_mount(str) {
    lower(str) == "default"
}
valid_proc_mount(str) {
    lower(str) == "unmasked"
}
