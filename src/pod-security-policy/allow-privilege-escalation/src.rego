package k8spspallowprivilegeescalationcontainer

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation[{"msg": msg, "details": {}}] {
    # spec.containers.securityContext.allowPrivilegeEscalation field is immutable.
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    input_allow_privilege_escalation(c)
    msg := sprintf("Privilege escalation container is not allowed: %v", [c.name])
}

input_allow_privilege_escalation(c) {
    not has_field(c, "securityContext")
}
input_allow_privilege_escalation(c) {
    not c.securityContext.allowPrivilegeEscalation == false
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
# has_field returns whether an object has a field
has_field(object, field) = true {
    object[field]
}
