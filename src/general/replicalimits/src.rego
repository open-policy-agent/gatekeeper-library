package k8sreplicalimits

object_name = input.review.object.metadata.name
object_kind = input.review.kind.kind

violation[{"msg": msg}] {
    spec := input.review.object.spec
    not input_replica_limit(spec)
    msg := sprintf("The provided number of replicas is not allowed for %v: %v. Allowed ranges: %v", [object_kind, object_name, input.parameters])
}

input_replica_limit(spec) {
    provided := spec.replicas
    count(input.parameters.ranges) > 0
    range := input.parameters.ranges[_]
    value_within_range(range, provided)
}

value_within_range(range, value) {
    range.min_replicas <= value
    range.max_replicas >= value
}
