package k8spspfsgroup

import rego.v1

import data.lib.exclude_update.is_update

violation contains {"msg": msg, "details": {}} if {
	# spec.securityContext.fsGroup field is immutable.
	not is_update(input.review)
	"rule" in object.keys(input.parameters)
	not input_fs_group_allowed(input.review.object.spec)

	msg := sprintf("The provided pod spec fsGroup is not allowed, pod: %v. Allowed fsGroup: %v", [
		input.review.object.metadata.name,
		input.parameters,
	])
}

input_fs_group_allowed(_) if {
	# RunAsAny - No range is required. Allows any fsGroup ID to be specified.
	input.parameters.rule == "RunAsAny"
}

input_fs_group_allowed(spec) if {
	# MustRunAs - Validates pod spec fsgroup against all ranges
	input.parameters.rule == "MustRunAs"
	some range in input.parameters.ranges
	value_within_range(range, spec.securityContext.fsGroup)
}

input_fs_group_allowed(spec) if {
	# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
	input.parameters.rule == "MayRunAs"
	not "securityContext" in object.keys(spec)
}

input_fs_group_allowed(spec) if {
	# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
	input.parameters.rule == "MayRunAs"
	not spec.securityContext.fsGroup
}

input_fs_group_allowed(spec) if {
	# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
	input.parameters.rule == "MayRunAs"
	some range in input.parameters.ranges
	value_within_range(range, spec.securityContext.fsGroup)
}

value_within_range(range, value) if {
	range.min <= value
	range.max >= value
}
