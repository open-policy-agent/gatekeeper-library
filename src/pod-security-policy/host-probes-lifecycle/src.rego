package k8spsphostprobeslifecycle

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation[{"msg": msg, "details": {}}] {
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    probe := c[probe_fields[_]]
    probe.httpGet.host != ""
    msg := sprintf("Container %v has probe with host field set: %v", [c.name, probe.httpGet.host])
}

violation[{"msg": msg, "details": {}}] {
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    probe := c[probe_fields[_]]
    probe.tcpSocket.host != ""
    msg := sprintf("Container %v has probe with host field set: %v", [c.name, probe.tcpSocket.host])
}

violation[{"msg": msg, "details": {}}] {
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    hook := c.lifecycle[lifecycle_fields[_]]
    hook.httpGet.host != ""
    msg := sprintf("Container %v has lifecycle hook with host field set: %v", [c.name, hook.httpGet.host])
}

violation[{"msg": msg, "details": {}}] {
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    hook := c.lifecycle[lifecycle_fields[_]]
    hook.tcpSocket.host != ""
    msg := sprintf("Container %v has lifecycle hook with host field set: %v", [c.name, hook.tcpSocket.host])
}

probe_fields := ["livenessProbe", "readinessProbe", "startupProbe"]

lifecycle_fields := ["postStart", "preStop"]

input_containers[c] {
    c := input.review.object.spec.containers[_]
}

input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}

input_containers[c] {
    c := input.review.object.spec.ephemeralContainers[_]
}
