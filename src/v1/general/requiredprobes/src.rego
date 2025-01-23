package k8srequiredprobes

import rego.v1

import data.lib.exclude_update.is_update

probe_type_set := {type | some type in input.parameters.probeTypes}

violation contains {"msg": msg} if {
	# Probe fields are immutable.
	not is_update(input.review)

	some container in input.review.object.spec.containers
	some probe in input.parameters.probes
	probe_is_missing(container, probe)
	msg := get_violation_message(container, input.review, probe)
}

probe_is_missing(ctr, probe) if not ctr[probe]

probe_is_missing(ctr, probe) if probe_field_empty(ctr, probe)

probe_field_empty(ctr, probe) if {
	probe_fields := object.keys(ctr[probe])
	diff_fields := probe_type_set - probe_fields
	count(diff_fields) == count(probe_type_set)
}

get_violation_message(container, review, probe) := sprintf("Container <%v> in your <%v> <%v> has no <%v>", [
	container.name, review.kind.kind,
	review.object.metadata.name,
	probe,
])
