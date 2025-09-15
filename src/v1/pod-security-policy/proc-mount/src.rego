package k8spspprocmount

import rego.v1

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
	# spec.containers.securityContext.procMount field is immutable.
	not is_update(input.review)

	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]

	not is_exempt(container)
	not input_proc_mount_type_allowed(allowed_proc_mount, container.securityContext.procMount)

	msg := sprintf(
		"ProcMount type is not allowed, container: %v. Allowed procMount types: %v",
		[container.name, allowed_proc_mount],
	)
}

input_proc_mount_type_allowed("default", cpm) if lower(cpm) == "default"

input_proc_mount_type_allowed("unmasked", _)

default allowed_proc_mount := "default"

allowed_proc_mount := provided if {
	provided := lower(input.parameters.procMount)
	provided in {"default", "unmasked"}
}
