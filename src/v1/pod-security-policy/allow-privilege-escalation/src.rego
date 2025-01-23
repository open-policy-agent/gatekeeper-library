package k8spspallowprivilegeescalationcontainer

import rego.v1

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
	# spec.containers.securityContext.allowPrivilegeEscalation field is immutable.
	not is_update(input.review)

	some c in input_containers
	not is_exempt(c)
	input_allow_privilege_escalation(c)
	msg := sprintf("Privilege escalation container is not allowed: %v", [c.name])
}

input_allow_privilege_escalation(c) if not "securityContext" in object.keys(c)

input_allow_privilege_escalation(c) if not c.securityContext.allowPrivilegeEscalation == false

input_containers contains container if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
}
