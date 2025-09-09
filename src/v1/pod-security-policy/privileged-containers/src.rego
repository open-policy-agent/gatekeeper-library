package k8spspprivileged

import rego.v1

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
	# spec.containers.privileged field is immutable.
	not is_update(input.review)

	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]

	not is_exempt(container)
	container.securityContext.privileged

	msg := sprintf(
		"Privileged container is not allowed: %v, securityContext: %v",
		[container.name, container.securityContext],
	)
}
