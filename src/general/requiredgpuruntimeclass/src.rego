package k8srequiredgpuruntimeclass

import data.lib.exempt_container.is_exempt

violation[{"msg": msg}] {
    pod_requests_gpu
    allowed := object.get(input, ["parameters", "allowedRuntimeClassNames"], [])
    count(allowed) > 0
    not has_allowed_runtime_class(allowed)
    msg := sprintf("Pod <%v> requests GPU resources but does not specify an allowed runtimeClassName (allowed: %v)", [input.review.object.metadata.name, allowed])
}

pod_requests_gpu {
    container := input_containers[_]
    not is_exempt(container)
    gpu := container.resources.limits["nvidia.com/gpu"]
    to_number(gpu) > 0
}

has_allowed_runtime_class(allowed) {
    rc := input.review.object.spec.runtimeClassName
    rc == allowed[_]
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
