package k8spspallowedusers

import rego.v1

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg} if {
	# runAsUser, runAsGroup, supplementalGroups, fsGroup fields are immutable.
	not is_update(input.review)

	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
	not is_exempt(container)

	some field in ["runAsUser", "runAsGroup", "supplementalGroups", "fsGroup"]

	msg := get_type_violation(field, container)
}

get_type_violation("runAsUser", container) := get_user_violation(input.parameters.runAsUser, container)

get_type_violation(field, container) := get_violation(field, input.parameters[field], container) if field != "runAsUser"

# RunAsUser (separate due to "MustRunAsNonRoot")
get_user_violation(params, container) := msg if {
	provided_user := field_value("runAsUser", container, input.review)
	not accept_users(params.rule, provided_user)
	msg := sprintf(
		"Container %v is attempting to run as disallowed user %v. Allowed runAsUser: %v",
		[container.name, provided_user, params],
	)
}

get_user_violation(params, container) := msg if {
	not field_value("runAsUser", container, input.review)
	params.rule = "MustRunAs"
	msg := sprintf("Container %v is attempting to run without a required securityContext/runAsUser", [container.name])
}

get_user_violation(params, container) := msg if {
	params.rule = "MustRunAsNonRoot"
	not field_value("runAsUser", container, input.review)
	not field_value("runAsNonRoot", container, input.review)
	msg := sprintf(
		"Container %v is attempting to run without a required securityContext/runAsNonRoot or securityContext/runAsUser != 0",
		[container.name],
	)
}

accept_users("RunAsAny", _)

accept_users("MustRunAsNonRoot", provided_user) if provided_user != 0

accept_users("MustRunAs", provided_user) if is_in_range(provided_user, input.parameters.runAsUser.ranges)

# Group Options
get_violation(field, params, container) := msg if {
	provided_value := field_value(field, container, input.review)
	not is_array(provided_value)
	not accept_value(params.rule, provided_value, params.ranges)
	msg := sprintf(
		"Container %v is attempting to run as disallowed group %v. Allowed %v: %v",
		[container.name, provided_value, field, params],
	)
}

# SupplementalGroups is array value
get_violation(field, params, container) := msg if {
	array_value := field_value(field, container, input.review)
	is_array(array_value)
	some provided_value in array_value
	not accept_value(params.rule, provided_value, params.ranges)
	msg := sprintf(
		"Container %v is attempting to run with disallowed supplementalGroups %v. Allowed %v: %v",
		[container.name, array_value, field, params],
	)
}

get_violation(field, params, container) := msg if {
	not field_value(field, container, input.review)
	params.rule == "MustRunAs"
	msg := sprintf(
		"Container %v is attempting to run without a required securityContext/%v. Allowed %v: %v",
		[container.name, field, field, params],
	)
}

accept_value("RunAsAny", _, _)

accept_value("MayRunAs", provided_value, ranges) := is_in_range(provided_value, ranges)

accept_value("MustRunAs", provided_value, ranges) := is_in_range(provided_value, ranges)

# If container level is provided, that takes precedence
field_value(field, container, _) := seccontext_field(field, container)

# If no container level exists, use pod level
field_value(field, container, review) := seccontext_field(field, review.object.spec) if {
	not has_seccontext_field(field, container)
	review.kind.kind == "Pod"
}

# Helper Functions
is_in_range(val, ranges) if count({1 | val >= ranges[j].min; val <= ranges[j].max}) > 0

has_seccontext_field(field, obj) if field in object.keys(obj.securityContext)

seccontext_field(field, obj) := obj.securityContext[field]
