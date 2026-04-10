package k8sgpuworkloadresources

missing(obj, field) = true {
  not obj[field]
}

missing(obj, field) = true {
  obj[field] == ""
}

# 10 ** 21
mem_multiple("E") = 1000000000000000000000 { true }

# 10 ** 18
mem_multiple("P") = 1000000000000000000 { true }

# 10 ** 15
mem_multiple("T") = 1000000000000000 { true }

# 10 ** 12
mem_multiple("G") = 1000000000000 { true }

# 10 ** 9
mem_multiple("M") = 1000000000 { true }

# 10 ** 6
mem_multiple("k") = 1000000 { true }

# 10 ** 3
mem_multiple("") = 1000 { true }

# Kubernetes accepts millibyte precision when it probably shouldn't.
# https://github.com/kubernetes/kubernetes/issues/28741
# 10 ** 0
mem_multiple("m") = 1 { true }

# 1000 * 2 ** 10
mem_multiple("Ki") = 1024000 { true }

# 1000 * 2 ** 20
mem_multiple("Mi") = 1048576000 { true }

# 1000 * 2 ** 30
mem_multiple("Gi") = 1073741824000 { true }

# 1000 * 2 ** 40
mem_multiple("Ti") = 1099511627776000 { true }

# 1000 * 2 ** 50
mem_multiple("Pi") = 1125899906842624000 { true }

# 1000 * 2 ** 60
mem_multiple("Ei") = 1152921504606846976000 { true }

get_suffix(mem) = suffix {
  not is_string(mem)
  suffix := ""
}

get_suffix(mem) = suffix {
  is_string(mem)
  count(mem) > 0
  suffix := substring(mem, count(mem) - 1, -1)
  mem_multiple(suffix)
}

get_suffix(mem) = suffix {
  is_string(mem)
  count(mem) > 1
  suffix := substring(mem, count(mem) - 2, -1)
  mem_multiple(suffix)
}

get_suffix(mem) = suffix {
  is_string(mem)
  count(mem) > 1
  not mem_multiple(substring(mem, count(mem) - 1, -1))
  not mem_multiple(substring(mem, count(mem) - 2, -1))
  suffix := ""
}

get_suffix(mem) = suffix {
  is_string(mem)
  count(mem) == 1
  not mem_multiple(substring(mem, count(mem) - 1, -1))
  suffix := ""
}

get_suffix(mem) = suffix {
  is_string(mem)
  count(mem) == 0
  suffix := ""
}

canonify_mem(orig) = new {
  is_number(orig)
  new := orig * 1000
}

canonify_mem(orig) = new {
  not is_number(orig)
  suffix := get_suffix(orig)
  raw := replace(orig, suffix, "")
  regex.match("^[0-9]+(\\.[0-9]+)?$", raw)
  new := to_number(raw) * mem_multiple(suffix)
}

violation[{"msg": msg}] {
  container := gpu_containers[_]
  not has_matching_gpu_request_and_limit(container)
  msg := sprintf("Container <%v> must set nvidia.com/gpu request equal to limit", [container.name])
}

violation[{"msg": msg}] {
  pod_requests_gpu
  container := enforced_containers[_]
  not is_exempt(container)
  not has_matching_memory_request_and_limit(container)
  msg := sprintf("Container <%v> in a GPU pod must set memory request equal to limit", [container.name])
}

violation[{"msg": msg}] {
  pod_requests_gpu
  container := enforced_containers[_]
  not is_exempt(container)
  not has_cpu_request(container)
  msg := sprintf("Container <%v> in a GPU pod must set a cpu request", [container.name])
}

pod_requests_gpu {
  gpu_containers[_]
}

gpu_containers[c] {
  c := all_containers[_]
  not is_exempt(c)
  requests_gpu(c)
}

enforced_containers[c] {
  c := input.review.object.spec.containers[_]
}

enforced_containers[c] {
  c := input.review.object.spec.initContainers[_]
}

all_containers[c] {
  c := enforced_containers[_]
}

all_containers[c] {
  c := input.review.object.spec.ephemeralContainers[_]
}

requests_gpu(container) {
  limits := object.get(object.get(container, "resources", {}), "limits", {})
  gpu := limits["nvidia.com/gpu"]
  to_number(gpu) > 0
}

requests_gpu(container) {
  requests := object.get(object.get(container, "resources", {}), "requests", {})
  gpu := requests["nvidia.com/gpu"]
  to_number(gpu) > 0
}

has_matching_gpu_request_and_limit(container) {
  requests := object.get(object.get(container, "resources", {}), "requests", {})
  limits := object.get(object.get(container, "resources", {}), "limits", {})
  gpu_request := requests["nvidia.com/gpu"]
  gpu_limit := limits["nvidia.com/gpu"]
  to_number(gpu_request) > 0
  to_number(gpu_limit) > 0
  to_number(gpu_request) == to_number(gpu_limit)
}

has_matching_memory_request_and_limit(container) {
  requests := object.get(object.get(container, "resources", {}), "requests", {})
  limits := object.get(object.get(container, "resources", {}), "limits", {})
  mem_request := requests["memory"]
  mem_limit := limits["memory"]
  canonify_mem(mem_request) == canonify_mem(mem_limit)
}

has_cpu_request(container) {
  requests := object.get(object.get(container, "resources", {}), "requests", {})
  not missing(requests, "cpu")
}

is_exempt(container) {
  exempt_images := object.get(input, ["parameters", "exemptImages"], [])
  img := container.image
  exemption := exempt_images[_]
  _matches_exemption(img, exemption)
}

_matches_exemption(img, exemption) {
  not endswith(exemption, "*")
  exemption == img
}

_matches_exemption(img, exemption) {
  endswith(exemption, "*")
  prefix := trim_suffix(exemption, "*")
  startswith(img, prefix)
}