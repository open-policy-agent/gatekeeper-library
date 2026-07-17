package k8sreplicalimits

object_name = input.review.object.metadata.name
object_kind = input.review.kind.kind

violation[{"msg": msg}] {
    # Scale requests for --replicas=0 may omit/empty spec; treat missing
    # replicas as 0 so ranges that allow zero do not false-positive.
    provided := object.get(input.review.object, ["spec", "replicas"], 0)
    count(input.parameters.ranges) > 0
    not input_replica_limit(provided)
    msg := sprintf("The provided number of replicas is not allowed for %v: %v. Allowed ranges: %v", [object_kind, object_name, input.parameters])
}

input_replica_limit(provided) {
    range := input.parameters.ranges[_]
    value_within_range(range, provided)
}

value_within_range(range, value) {
    range.min_replicas <= value
    range.max_replicas >= value
}
