package k8spspforbiddensysctls

violation[{"msg": msg, "details": {}}] {
    sysctl := input.review.object.spec.securityContext.sysctls[_].name
    forbidden_sysctl(sysctl)
    msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.forbiddenSysctls])
}

# * may be used to forbid all sysctls
forbidden_sysctl(sysctl) {
    input.parameters.forbiddenSysctls[_] == "*"
}

forbidden_sysctl(sysctl) {
    input.parameters.forbiddenSysctls[_] == sysctl
}

forbidden_sysctl(sysctl) {
    startswith(sysctl, trim(input.parameters.forbiddenSysctls[_], "*"))
}
