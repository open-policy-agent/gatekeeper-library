package k8spspforbiddensysctls

import rego.v1

import data.lib.exclude_update.is_update

# Block if forbidden
violation contains {"msg": msg, "details": {}} if {
	# spec.securityContext.sysctls field is immutable.
	not is_update(input.review)
	sysctl := input.review.object.spec.securityContext.sysctls[_].name
	forbidden_sysctl(sysctl)
	msg := sprintf(
		"The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v",
		[sysctl, input.review.object.metadata.name, input.parameters.forbiddenSysctls],
	)
}

# Block if not explicitly allowed
violation contains {"msg": msg, "details": {}} if {
	not is_update(input.review)
	sysctl := input.review.object.spec.securityContext.sysctls[_].name
	not allowed_sysctl(sysctl)
	msg := sprintf(
		"The sysctl %v is not explicitly allowed, pod: %v. Allowed sysctls: %v",
		[sysctl, input.review.object.metadata.name, allowed_sysctl_string],
	)
}

# * may be used to forbid all sysctls
forbidden_sysctl(_) if "*" in input.parameters.forbiddenSysctls

forbidden_sysctl(sysctl) if sysctl in input.parameters.forbiddenSysctls

forbidden_sysctl(sysctl) if {
	some forbidden in input.parameters.forbiddenSysctls
	endswith(forbidden, "*")
	startswith(sysctl, trim_suffix(forbidden, "*"))
}

# * may be used to allow all sysctls
allowed_sysctl(_) if "*" in input.parameters.allowedSysctls

allowed_sysctl(sysctl) if sysctl in input.parameters.allowedSysctls

allowed_sysctl(sysctl) if {
	some allowed in input.parameters.allowedSysctls
	endswith(allowed, "*")
	startswith(sysctl, trim_suffix(allowed, "*"))
}

allowed_sysctl(_) if not input.parameters.allowedSysctls

default allowed_sysctl_string := "unspecified"

allowed_sysctl_string := input.parameters.allowedSysctls
