package k8srequiredprobes

probe_type_set = probe_types {
    probe_types := {type | type := input.parameters.probeTypes[_]}
}

violation[{"msg": msg}] {
    not input.parameters.onlyServices
    container := input.review.object.spec.containers[_]
    probe := input.parameters.probes[_]
    probe_is_missing(container, probe)
    custom_msg := object.get(input.parameters, "customViolationMessage", "")
    msg := trim(sprintf("Container <%v> in this <%v> has no <%v>. %v", [container.name, input.review.kind.kind, probe, custom_msg]), " ")
}

violation[{"msg": msg}] {
    input.parameters.onlyServices
    container := input.review.object.spec.containers[_]
    probe := input.parameters.probes[_]
    probe_is_missing(container, probe)

    obj := input.review.object
    svc := data.inventory.namespace[obj.metadata.namespace]["v1"]["Service"][_]
    matchLabels := { [label, value] | some label; value := svc.spec.selector[label] }
    labels := { [label, value] | some label; value := obj.metadata.labels[label] }
    count(matchLabels - labels) == 0
    matching_ports := [p | p := svc.spec.ports[_].targetPort; has_port(p, container)]
    count(matching_ports) > 0

    custom_msg := object.get(input.parameters, "customViolationMessage", "")
    msg := trim(sprintf("Container <%v> in this <%v> has no <%v> and is selected by service <%v> with targetPort(s) %v. %v", [container.name, input.review.kind.kind, probe, svc.metadata.name, matching_ports, custom_msg]), " ")
}

has_port(targetPort, container){
    targetPort == container.ports[_].containerPort
}

has_port(targetPort, container){
    targetPort == container.ports[_].name
}

probe_is_missing(ctr, probe) = true {
    not ctr[probe]
}

probe_is_missing(ctr, probe) = true {
    probe_field_empty(ctr, probe)
}

probe_field_empty(ctr, probe) = true {
    probe_fields := {field | ctr[probe][field]}
    diff_fields := probe_type_set - probe_fields
    count(diff_fields) == count(probe_type_set)
}
