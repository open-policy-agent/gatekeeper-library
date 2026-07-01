package k8spspforbiddensysctls

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update

# Block if forbidden
violation contains {"msg": msg, "details": {}} if {
    # spec.securityContext.sysctls field is immutable.
    not is_update(input.review)

    sysctl := input.review.object.spec.securityContext.sysctls[_].name
    forbidden_sysctl(sysctl)
    msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.forbiddenSysctls])
}

# Block if not explicitly allowed
violation contains {"msg": msg, "details": {}} if {
    not is_update(input.review)
    sysctl := input.review.object.spec.securityContext.sysctls[_].name
    not allowed_sysctl(sysctl)
    allowmsg := allowed_sysctl_string()
    msg := sprintf("The sysctl %v is not explicitly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.review.object.metadata.name, allowmsg])
}

# * may be used to forbid all sysctls
forbidden_sysctl(_) if {
    input.parameters.forbiddenSysctls[_] == "*"
}

forbidden_sysctl(sysctl) if {
    input.parameters.forbiddenSysctls[_] == sysctl
}

forbidden_sysctl(sysctl) if {
    forbidden := input.parameters.forbiddenSysctls[_]
    endswith(forbidden, "*")
    startswith(sysctl, trim_suffix(forbidden, "*"))
}

# * may be used to allow all sysctls
allowed_sysctl(_) if {
    input.parameters.allowedSysctls[_] == "*"
}

allowed_sysctl(sysctl) if {
    input.parameters.allowedSysctls[_] == sysctl
}

allowed_sysctl(sysctl) if {
    allowed := input.parameters.allowedSysctls[_]
    endswith(allowed, "*")
    startswith(sysctl, trim_suffix(allowed, "*"))
}

allowed_sysctl(_) if {
    not input.parameters.allowedSysctls
}

allowed_sysctl_string := out if {
    not input.parameters.allowedSysctls
    out = "unspecified"
}

allowed_sysctl_string := out if {
    out = input.parameters.allowedSysctls
}
