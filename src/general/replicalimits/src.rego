package k8sreplicalimits

deployment_name = input.review.object.metadata.name

violation[{"msg": msg}] {
    spec := input.review.object.spec
    not input_replica_limit(spec)
    msg := sprintf("The provided number of replicas is not allowed for deployment: %v. Allowed ranges: %v", [deployment_name, input.parameters])
}

input_replica_limit(spec) {
    provided := input.review.object.spec.replicas
    count(input.parameters.ranges) > 0
    range := input.parameters.ranges[_]
    value_within_range(range, provided)
}

value_within_range(range, value) {
    range.min_replicas <= value
    range.max_replicas >= value
}
