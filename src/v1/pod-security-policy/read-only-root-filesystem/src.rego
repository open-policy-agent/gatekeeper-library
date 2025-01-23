package k8spspreadonlyrootfilesystem

import rego.v1

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
	# spec.containers.readOnlyRootFilesystem field is immutable.
	not is_update(input.review)

	some container in input_containers
	not is_exempt(container)
	input_read_only_root_fs(container)
	msg := sprintf("only read-only root filesystem container is allowed: %v", [container.name])
}

input_read_only_root_fs(c) if not "securityContext" in object.keys(c)

input_read_only_root_fs(c) if not c.securityContext.readOnlyRootFilesystem == true

input_containers contains container if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
}
