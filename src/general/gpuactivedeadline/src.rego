package k8sgpuactivedeadline

import data.lib.exempt_container.is_exempt

violation[{"msg": msg}] {
    pod_requests_gpu
    not has_active_deadline
    msg := sprintf("Pod <%v> requests GPU resources but does not set activeDeadlineSeconds", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
    pod_requests_gpu
    has_active_deadline
    max_deadline := object.get(input, ["parameters", "maxActiveDeadlineSeconds"], 0)
    max_deadline > 0
    deadline := input.review.object.spec.activeDeadlineSeconds
    deadline > max_deadline
    msg := sprintf("Pod <%v> sets activeDeadlineSeconds to %v, which exceeds the maximum allowed %v", [input.review.object.metadata.name, deadline, max_deadline])
}

pod_requests_gpu {
    container := input_containers[_]
    not is_exempt(container)
    gpu := container.resources.limits["nvidia.com/gpu"]
    to_number(gpu) > 0
}

has_active_deadline {
    input.review.object.spec.activeDeadlineSeconds
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
