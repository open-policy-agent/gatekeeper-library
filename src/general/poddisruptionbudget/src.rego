package k8spoddisruptionbudget

compute_min_max_available(avail_raw, replicas) = avail {
  is_percentage(avail_raw)
  avail = replicas * parse_percentage(avail_raw)
}

compute_min_max_available(avail_raw, _) = avail {
  not is_percentage(avail_raw)
  avail = avail_raw
}

is_percentage(x) = true {
  endswith(x, "%")
}

parse_percentage(avail) = value_num {
 value_num := to_number(trim(avail,"%"))/100
}

violation[{"msg": msg}] {
  input.review.kind.kind == "PodDisruptionBudget"
  pdb := input.review.object

  not valid_max_unavailable(pdb)
  msg := sprintf(
    "PodDisruptionBudget <%v> has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
    [pdb.metadata.name],
  )
}

violation[{"msg": msg}] {
  obj := input.review.object
  obj.kind != "PodDisruptionBudget"
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
  obj.kind != "PodDisruptionBudget"
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

valid_pdb_min_available(obj, pdb) {
  # default to -1 if minAvailable is not set so valid_pdb_min_available is always true
  # for objects with >= 0 replicas. If minAvailable defaults to >= 0, objects with
  # replicas field might violate this constraint if they are equal to the default set here
  min_available_raw := object.get(pdb.spec, "minAvailable", -1)
  min_available := compute_min_max_available(min_available_raw, obj.spec.replicas)
  obj.spec.replicas > min_available
}

valid_pdb_max_unavailable(obj, pdb) {
  # default to 1 if maxUnavailable is not set so valid_pdb_max_unavailable always returns true.
  # If maxUnavailable defaults to 0, it violates this constraint because all pods needs to be
  # available and no pods can be evicted voluntarily
  max_unavailable_raw := object.get(pdb.spec, "maxUnavailable", 1)
  max_unavailable := compute_min_max_available(max_unavailable_raw, obj.spec.replicas)
  max_unavailable > 0
}

valid_max_unavailable(pdb) {
  # default to 1 if maxUnavailable is not set so valid_pdb_max_unavailable always returns true.
  # If maxUnavailable defaults to 0, it violates this constraint because all pods needs to be
  # available and no pods can be evicted voluntarily
  max_unavailable := object.get(pdb.spec, "maxUnavailable", 1)
  max_unavailable > 0
}