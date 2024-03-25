package k8spoddisruptionbudget

import future.keywords

violation[{"msg": msg}] {
  input.review.kind.kind == "PodDisruptionBudget"
  pdb := input.review.object

  not valid_pdb_max_unavailable(input.review, pdb)
  msg := sprintf(
    "PodDisruptionBudget <%v> has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
    [pdb.metadata.name],
  )
}

violation[{"msg": msg}] {
  obj := input.review.object
  pdb := data.inventory.namespace[obj.metadata.namespace]["policy/v1"].PodDisruptionBudget[_]

  matchLabels := { [label, value] | some label; value := pdb.spec.selector.matchLabels[label] }
  labels := { [label, value] | some label; value := obj.spec.selector.matchLabels[label] }
  count(matchLabels - labels) == 0

  not valid_pdb_max_unavailable(obj, pdb)
  msg := sprintf(
    "%v <%v> has been selected by PodDisruptionBudget <%v> but has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
    [obj.kind, obj.metadata.name, pdb.metadata.name],
  )
}

violation[{"msg": msg}] {
  obj := input.review.object
  pdb := data.inventory.namespace[obj.metadata.namespace]["policy/v1"].PodDisruptionBudget[_]
  
  matchLabels := { [label, value] | some label; value := pdb.spec.selector.matchLabels[label] }
  labels := { [label, value] | some label; value := obj.spec.selector.matchLabels[label] }
  count(matchLabels - labels) == 0

  not valid_pdb_min_available(obj, pdb)
  msg := sprintf(
    "%v <%v> has %v replica(s) but PodDisruptionBudget <%v> has minAvailable of %v, PodDisruptionBudget count should always be lower than replica(s), and not used when replica(s) is set to 1",
    [obj.kind, obj.metadata.name, obj.spec.replicas, pdb.metadata.name, pdb.spec.minAvailable],
  )
}

min_available(obj, pdb) = new if {
  # if its a percentage, it will return the number of pods that need
  # to be available rounded up (that's how Kubernetes calculates it).
  # if its a number, return that number
	endswith(pdb.spec.minAvailable, "%")

	# convert % to a number, if this is 50%, then 50/100 = 0.5
	per := to_number(replace(pdb.spec.minAvailable, "%", "")) / 100

	# round up to the nearest integer based on replicas
	# if replicas is 3, then 3 * 0.5 = 1.5, ceil(1.5) = 2
	new := ceil(obj.spec.replicas * per)
}

min_available(_, pdb) = new if {
	is_number(pdb.spec.minAvailable)
	new := object.get(pdb.spec, "minAvailable", -1)
}

min_available(_, pdb) = new if {
  # default to -1 if minAvailable is not set so valid_pdb_min_available is always true
  # for objects with >= 0 replicas. If minAvailable defaults to >= 0, objects with
  # replicas field might violate this constraint if they are equal to the default set here
	not pdb.spec.minAvailable
	new := -1
}

valid_pdb_min_available(obj, pdb) if {
	obj.spec.replicas > min_available(obj, pdb)
}

max_unavailable(obj, pdb) = new if {
  # if its a percentage, it will return the number of pods that need
  # to be available rounded down (that's how Kubernetes calculates it).
  # if its a number, return that number, if unset return default of 1
	endswith(pdb.spec.maxUnavailable, "%")

	# convert % to a number, if this is 50%, then 50/100 = 0.5
	per := to_number(replace(pdb.spec.maxUnavailable, "%", "")) / 100

	# round down to the nearest integer based on replicas
	# if replicas is 3, then 3 * 0.5 = 1.5, ceil(1.5) = 2
	new := ceil(obj.spec.replicas * per)
}

max_unavailable(_, pdb) = new if {
	is_number(pdb.spec.maxUnavailable)
	new := object.get(pdb.spec, "maxUnavailable", 1)
}

max_unavailable(_, pdb) = new if {
  # default to 1 if maxUnavailable is not set so valid_pdb_max_unavailable always returns true.
  # If maxUnavailable defaults to 0, it violates this constraint because all pods needs to be
  # available and no pods can be evicted voluntarily
	not pdb.spec.maxUnavailable
	new := 1
}

valid_pdb_max_unavailable(obj, pdb) if {
	max_unavailable(obj, pdb) > 0
}
