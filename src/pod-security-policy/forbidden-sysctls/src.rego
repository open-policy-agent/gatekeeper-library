package k8spspforbiddensysctls

import data.lib.exclude_update.is_update

# Block if forbidden
violation[{"msg": msg, "details": {}}] {
    # spec.securityContext.sysctls field is immutable.
    not is_update(input.review)

    sysctl := input.review.object.spec.securityContext.sysctls[_].name
    forbidden_sysctl(sysctl)
    msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.forbiddenSysctls])
}

# Block if not explicitly allowed
violation[{"msg": msg, "details": {}}] {
    not is_update(input.review)
    sysctl := input.review.object.spec.securityContext.sysctls[_].name
    not allowed_sysctl(sysctl)
    allowmsg := allowed_sysctl_string()
    msg := sprintf("The sysctl %v is not explicitly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.review.object.metadata.name, allowmsg])
}

# * may be used to forbid all sysctls
forbidden_sysctl(_) {
    input.parameters.forbiddenSysctls[_] == "*"
}

forbidden_sysctl(sysctl) {
    input.parameters.forbiddenSysctls[_] == sysctl
}

forbidden_sysctl(sysctl) {
    forbidden := input.parameters.forbiddenSysctls[_]
    endswith(forbidden, "*")
    startswith(sysctl, trim_suffix(forbidden, "*"))
}

# * may be used to allow all sysctls
allowed_sysctl(_) {
    input.parameters.allowedSysctls[_] == "*"
}

allowed_sysctl(sysctl) {
    input.parameters.allowedSysctls[_] == sysctl
}

allowed_sysctl(sysctl) {
    allowed := input.parameters.allowedSysctls[_]
    endswith(allowed, "*")
    startswith(sysctl, trim_suffix(allowed, "*"))
}

allowed_sysctl(_) {
    not input.parameters.allowedSysctls
}
allowed_sysctl_string() = out {
    not input.parameters.allowedSysctls
    out = "unspecified"
}
allowed_sysctl_string() = out {
    out = input.parameters.allowedSysctls
}
