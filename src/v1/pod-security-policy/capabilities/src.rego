package capabilities

import rego.v1

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg} if {
	# spec.containers.securityContext.capabilities field is immutable.
	not is_update(input.review)

	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]

	not is_exempt(container)
	has_disallowed_capabilities(container)

	msg := sprintf(
		"%s <%v> has a disallowed capability. Allowed capabilities are %v",
		[trim_suffix(type, "s"), container.name, get_default(input.parameters, "allowedCapabilities", "NONE")],
	)
}

violation contains {"msg": msg} if {
	not is_update(input.review)

	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]

	not is_exempt(container)
	missing_drop_capabilities(container)

	msg := sprintf(
		"%s <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"",
		[trim_suffix(type, "s"), container.name, input.parameters.requiredDropCapabilities],
	)
}

has_disallowed_capabilities(container) if {
	allowed := {c | c := lower(input.parameters.allowedCapabilities[_])}
	not allowed["*"]
	capabilities := {c | c := lower(container.securityContext.capabilities.add[_])}

	count(capabilities - allowed) > 0
}

missing_drop_capabilities(container) if {
	must_drop := {c | c := lower(input.parameters.requiredDropCapabilities[_])}
	dropped := {c | c := lower(container.securityContext.capabilities.drop[_])}

	count(must_drop - dropped) > 0
	count({"all"} - dropped) > 0
}

get_default(obj, param, _) := obj[param]

get_default(obj, param, _default) := _default if {
	not obj[param]
	not obj[param] == false
}
