package k8spsphostnamespace

import rego.v1

import data.lib.exclude_update.is_update

violation contains {"msg": msg, "details": {}} if {
	# spec.hostPID and spec.hostIPC fields are immutable.
	not is_update(input.review)

	input_share_hostnamespace

	msg := sprintf("Sharing the host namespace is not allowed: %v", [input.review.object.metadata.name])
}

input_share_hostnamespace if input.review.object.spec.hostPID

input_share_hostnamespace if input.review.object.spec.hostIPC
