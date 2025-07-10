package k8sreplicalimits

import rego.v1

violation contains {"msg": msg} if {
	not input_replica_limit(input.review.object.spec)
	msg := sprintf(
		"The provided number of replicas is not allowed for %v: %v. Allowed ranges: %v",
		[input.review.kind.kind, input.review.object.metadata.name, input.parameters],
	)
}

input_replica_limit(spec) if {
	some range in input.parameters.ranges
	range.min_replicas <= spec.replicas
	range.max_replicas >= spec.replicas
}
