package k8srequiredprobes

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update

probe_type_set := probe_types if {
    probe_types := {type | type := input.parameters.probeTypes[_]}
}

violation contains ({"msg": msg}) if {

    # Probe fields are immutable.
    not is_update(input.review)

    container := input.review.object.spec.containers[_]
    probe := input.parameters.probes[_]
    probe_is_missing(container, probe)
    msg := get_violation_message(container, input.review, probe)
}

probe_is_missing(ctr, probe) if {
    not ctr[probe]
}

probe_is_missing(ctr, probe) if {
    probe_field_empty(ctr, probe)
}

probe_field_empty(ctr, probe) if {
    probe_fields := {field | ctr[probe][field]}
    diff_fields := probe_type_set - probe_fields
    count(diff_fields) == count(probe_type_set)
}

get_violation_message(container, review, probe) := msg if {
    msg := sprintf("Container <%v> in your <%v> <%v> has no <%v>", [container.name, review.kind.kind, review.object.metadata.name, probe])
}
