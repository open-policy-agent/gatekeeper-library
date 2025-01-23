package k8spspselinux

import rego.v1

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

# Disallow top level custom SELinux options
violation contains {"msg": msg, "details": {}} if {
	# spec.securityContext.seLinuxOptions field is immutable.
	not is_update(input.review)
	not input_se_linux_options_allowed(input.review.object.spec.securityContext.seLinuxOptions)

	msg := sprintf("SELinux options is not allowed, pod: %v. Allowed options: %v", [
		input.review.object.metadata.name,
		input.parameters.allowedSELinuxOptions,
	])
}

# Disallow container level custom SELinux options
violation contains {"msg": msg, "details": {}} if {
	# spec.containers.securityContext.seLinuxOptions field is immutable.
	not is_update(input.review)

	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]

	not is_exempt(container)
	not input_se_linux_options_allowed(container.securityContext.seLinuxOptions)

	msg := sprintf("SELinux options is not allowed, pod: %v, container: %v. Allowed options: %v", [
		input.review.object.metadata.name,
		container.name, input.parameters.allowedSELinuxOptions,
	])
}

input_se_linux_options_allowed(options) if {
	some params in input.parameters.allowedSELinuxOptions
	field_allowed("level", options, params)
	field_allowed("role", options, params)
	field_allowed("type", options, params)
	field_allowed("user", options, params)
}

field_allowed(field, options, params) if params[field] == options[field]

field_allowed(field, options, _) if not field in object.keys(options)
