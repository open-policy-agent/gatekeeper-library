package k8spoddisruptionbudget

import rego.v1

violation contains {"msg": msg} if {
	input.review.kind.kind == "PodDisruptionBudget"
	pdb := input.review.object

	not valid_pdb_max_unavailable(pdb)
	msg := sprintf(
		"PodDisruptionBudget <%v> has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
		[pdb.metadata.name],
	)
}

violation contains {"msg": msg} if {
	obj := input.review.object
	labels := {[label, value] | some label, value in obj.spec.selector.matchLabels}

	some pdb in data.inventory.namespace[obj.metadata.namespace]["policy/v1"].PodDisruptionBudget

	match_labels := {[label, value] | some label, value in pdb.spec.selector.matchLabels}
	count(match_labels - labels) == 0

	not valid_pdb_max_unavailable(pdb)
	msg := sprintf(
		# regal ignore:line-length
		"%v <%v> has been selected by PodDisruptionBudget <%v> but has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
		[obj.kind, obj.metadata.name, pdb.metadata.name],
	)
}

violation contains {"msg": msg} if {
	obj := input.review.object
	labels := {[label, value] | some label, value in obj.spec.selector.matchLabels}

	some pdb in data.inventory.namespace[obj.metadata.namespace]["policy/v1"].PodDisruptionBudget

	match_labels := {[label, value] | some label, value in pdb.spec.selector.matchLabels}
	count(match_labels - labels) == 0

	not valid_pdb_min_available(obj, pdb)
	msg := sprintf(
		# regal ignore:line-length
		"%v <%v> has %v replica(s) but PodDisruptionBudget <%v> has minAvailable of %v, PodDisruptionBudget count should always be lower than replica(s), and not used when replica(s) is set to 1",
		[obj.kind, obj.metadata.name, obj.spec.replicas, pdb.metadata.name, pdb.spec.minAvailable],
	)
}

valid_pdb_min_available(obj, pdb) if {
	# default to -1 if minAvailable is not set so valid_pdb_min_available is always true
	# for objects with >= 0 replicas. If minAvailable defaults to >= 0, objects with
	# replicas field might violate this constraint if they are equal to the default set here
	min_available := object.get(pdb.spec, "minAvailable", -1)
	obj.spec.replicas > min_available
}

valid_pdb_max_unavailable(pdb) if {
	# default to 1 if maxUnavailable is not set so valid_pdb_max_unavailable always returns true.
	# If maxUnavailable defaults to 0, it violates this constraint because all pods needs to be
	# available and no pods can be evicted voluntarily
	max_unavailable := object.get(pdb.spec, "maxUnavailable", 1)
	max_unavailable > 0
}
