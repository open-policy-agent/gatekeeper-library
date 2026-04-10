package k8sgpunodetargeting

violation[{"msg": msg}] {
  pod_requests_gpu
  label_key := object.get(input.parameters, "nodeLabelKey", "")
  label_key != ""
  not has_matching_node_selector(label_key)
  not has_matching_node_affinity(label_key)
  label_values := object.get(input.parameters, "nodeLabelValues", [])
  msg := violation_message(label_key, label_values)
}

violation_message(label_key, label_values) = msg {
  count(label_values) == 0
  msg := sprintf("Pod <%v> requests GPU resources but does not target nodes with label key <%v> using node affinity or nodeSelector", [input.review.object.metadata.name, label_key])
}

violation_message(label_key, label_values) = msg {
  count(label_values) > 0
  msg := sprintf("Pod <%v> requests GPU resources but does not target nodes with label <%v> matching one of <%v> using node affinity or nodeSelector", [input.review.object.metadata.name, label_key, label_values])
}

pod_requests_gpu {
  container := all_containers[_]
  not is_exempt(container)
  requests_gpu(container)
}

all_containers[c] {
  c := input.review.object.spec.containers[_]
}

all_containers[c] {
  c := input.review.object.spec.initContainers[_]
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

has_matching_node_selector(label_key) {
  selector := input.review.object.spec.nodeSelector
  value := selector[label_key]
  value != ""
  label_values := object.get(input.parameters, "nodeLabelValues", [])
  count(label_values) == 0
}

has_matching_node_selector(label_key) {
  selector := input.review.object.spec.nodeSelector
  value := selector[label_key]
  label_values := object.get(input.parameters, "nodeLabelValues", [])
  label_values[_] == value
}

has_matching_node_affinity(label_key) {
  term := input.review.object.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[_]
  expr := term.matchExpressions[_]
  expr.key == label_key
  label_values := object.get(input.parameters, "nodeLabelValues", [])
  count(label_values) == 0
  expr.operator == "Exists"
}

has_matching_node_affinity(label_key) {
  term := input.review.object.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[_]
  expr := term.matchExpressions[_]
  expr.key == label_key
  label_values := object.get(input.parameters, "nodeLabelValues", [])
  count(label_values) > 0
  expr.operator == "In"
  expr.values[_] == label_values[_]
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