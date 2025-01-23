package k8spsphostnetworkingports

import rego.v1

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
	# spec.hostNetwork field is immutable.
	not is_update(input.review)

	input_share_hostnetwork(input.review.object)
	msg := sprintf(
		"The specified hostNetwork and hostPort are not allowed, pod: %v. Allowed values: %v",
		[input.review.object.metadata.name, input.parameters],
	)
}

input_share_hostnetwork(o) if {
	not input.parameters.hostNetwork
	o.spec.hostNetwork
}

input_share_hostnetwork(_) if {
	host_port := input_containers[_].ports[_].hostPort
	host_port < input.parameters.min
}

input_share_hostnetwork(_) if {
	host_port := input_containers[_].ports[_].hostPort
	host_port > input.parameters.max
}

input_containers contains container if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
	not is_exempt(container)
}
