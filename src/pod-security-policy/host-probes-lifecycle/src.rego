package k8spsphostprobeslifecycle

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation[{"msg": msg, "details": {}}] {
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    probe := get_probe(c)
    probe.httpGet.host != ""
    msg := sprintf("Container %v has probe with host field set: %v", [c.name, probe.httpGet.host])
}

violation[{"msg": msg, "details": {}}] {
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    probe := get_probe(c)
    probe.tcpSocket.host != ""
    msg := sprintf("Container %v has probe with host field set: %v", [c.name, probe.tcpSocket.host])
}

violation[{"msg": msg, "details": {}}] {
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    hook := get_lifecycle_hook(c)
    hook.httpGet.host != ""
    msg := sprintf("Container %v has lifecycle hook with host field set: %v", [c.name, hook.httpGet.host])
}

violation[{"msg": msg, "details": {}}] {
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    hook := get_lifecycle_hook(c)
    hook.tcpSocket.host != ""
    msg := sprintf("Container %v has lifecycle hook with host field set: %v", [c.name, hook.tcpSocket.host])
}

get_probe(c) = probe {
    probe := c.livenessProbe
}

get_probe(c) = probe {
    probe := c.readinessProbe
}

get_probe(c) = probe {
    probe := c.startupProbe
}

get_lifecycle_hook(c) = hook {
    hook := c.lifecycle.postStart
}

get_lifecycle_hook(c) = hook {
    hook := c.lifecycle.preStop
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}

input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}

input_containers[c] {
    c := input.review.object.spec.ephemeralContainers[_]
}
