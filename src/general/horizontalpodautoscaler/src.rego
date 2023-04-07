package k8shorizontalpodautoscaler

violation[{"msg": msg}] {
  input.review.kind.kind == "HorizontalPodAutoscaler"
  hpa := input.review.object

  not input_replica_limit(hpa)
  msg := sprintf("The %v <%v> minReplicas %v or maxReplicas %v is not allowed: %v. Allowed ranges: %v", [hpa.kind, hpa.metadata.name, hpa.spec.minReplicas, hpa.spec.maxReplicas, input.parameters.ranges])
}

violation[{"msg": msg}] {
  input.review.kind.kind == "HorizontalPodAutoscaler"
  hpa := input.review.object

  not input_replica_spread(hpa)
  
  msg := sprintf("The %v <%v> is configured with minReplicas %v and maxReplicas %v which is a spread of %v replica(s). The spread must be at least %v replica(s)", [hpa.kind, hpa.metadata.name, hpa.spec.minReplicas, hpa.spec.maxReplicas, hpa.spec.maxReplicas - hpa.spec.minReplicas, input.parameters.minimumReplicaSpread])
}

violation[{"msg": msg}] {
  input.review.kind.kind == "HorizontalPodAutoscaler"
  hpa := input.review.object
  input.parameters.enforceScaleTargetRef
  
  not data.inventory.namespace[hpa.metadata.namespace][hpa.spec.scaleTargetRef.apiVersion][hpa.spec.scaleTargetRef.kind][hpa.spec.scaleTargetRef.name]
  msg := sprintf("The HorizontalPodAutoscaler <%v> has a scaleTargetRef of <%v/%v> but it does not exist. The scaleTargetRef for the HorizontalPodAutoscaler must exist", [hpa.metadata.name, hpa.spec.scaleTargetRef.kind, hpa.spec.scaleTargetRef.name])
}

input_replica_limit(hpa) {
    count(input.parameters.ranges) > 0
    range := input.parameters.ranges[_]
    value_within_range(range, hpa.spec.minReplicas, hpa.spec.maxReplicas)
}

value_within_range(range, min_provided, max_provided) {
    range.min_replicas <= min_provided
    range.max_replicas >= max_provided
}

input_replica_spread(hpa) {
    input.parameters.minimumReplicaSpread
    (hpa.spec.maxReplicas - hpa.spec.minReplicas) >= input.parameters.minimumReplicaSpread
}
