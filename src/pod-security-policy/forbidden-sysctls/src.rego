package k8spspforbiddensysctls

# Block if forbidden
violation[{"msg": msg, "details": {}}] {
    sysctl := input.review.object.spec.securityContext.sysctls[_].name
    forbidden_sysctl(sysctl)
    msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.forbiddenSysctls])
}

# Block if not explicitly allowed
violation[{"msg": msg, "details": {}}] {
    sysctl := input.review.object.spec.securityContext.sysctls[_].name
    not allowed_sysctl(sysctl)
    msg := sprintf("The sysctl %v is not explictly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.allowedSysctls])
}

# * may be used to forbid all sysctls
forbidden_sysctl(sysctl) {
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
allowed_sysctl(sysctl) {
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
