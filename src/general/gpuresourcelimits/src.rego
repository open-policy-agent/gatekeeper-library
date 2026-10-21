package k8sgpuresourcelimits

import data.lib.exempt_container.is_exempt

violation[{"msg": msg}] {
    container := input_containers[_]
    not is_exempt(container)
    gpu_count := to_number(container.resources.limits["nvidia.com/gpu"])
    gpu_count > 0
    max_gpu := object.get(input, ["parameters", "maxGpuPerContainer"], 0)
    max_gpu > 0
    gpu_count > max_gpu
    msg := sprintf("Container <%v> requests %v GPUs, which exceeds the maximum allowed %v", [container.name, gpu_count, max_gpu])
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
