package k8spspprocmount

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
    # spec.containers.securityContext.procMount field is immutable.
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    allowedProcMount := get_allowed_proc_mount(input)
    not input_proc_mount_type_allowed(allowedProcMount, c)
    msg := sprintf("ProcMount type is not allowed, container: %v. Allowed procMount types: %v", [c.name, allowedProcMount])
}

input_proc_mount_type_allowed(allowedProcMount, c) if {
    allowedProcMount == "default"
    lower(c.securityContext.procMount) == "default"
}

input_proc_mount_type_allowed(allowedProcMount, _) if {
    allowedProcMount == "unmasked"
}

input_containers contains c if {
    c := input.review.object.spec.containers[_]
    c.securityContext.procMount != null
}

input_containers contains c if {
    c := input.review.object.spec.initContainers[_]
    c.securityContext.procMount != null
}

input_containers contains c if {
    c := input.review.object.spec.ephemeralContainers[_]
    c.securityContext.procMount != null
}

get_allowed_proc_mount(arg) := out if {
    not arg.parameters
    out = "default"
}

get_allowed_proc_mount(arg) := out if {
    not arg.parameters.procMount
    out = "default"
}

get_allowed_proc_mount(arg) := out if {
    arg.parameters.procMount
    not valid_proc_mount(arg.parameters.procMount)
    out = "default"
}

get_allowed_proc_mount(arg) := out if {
    valid_proc_mount(arg.parameters.procMount)
    out = lower(arg.parameters.procMount)
}

valid_proc_mount(str) if {
    lower(str) == "default"
}

valid_proc_mount(str) if {
    lower(str) == "unmasked"
}
