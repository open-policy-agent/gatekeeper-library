package k8spoddisruptionbudget

violation[{"msg": msg}] {
  input.review.kind.kind == "PodDisruptionBudget"
  pdb := input.review.object

  not valid_pdb_max_unavailable(pdb)
  msg := sprintf(
    "PodDisruptionBudget <%v> has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
    [pdb.metadata.name],
  )
}

violation[{"msg": msg}] {
  input.review.kind.kind == "PodDisruptionBudget"
  pdb := input.review.object

  obj := data.inventory.namespace[pdb.metadata.namespace][_][_][_]
  obj.spec.selector.matchLabels == pdb.spec.selector.matchLabels

  not valid_pdb_min_available(obj, pdb)
  msg := sprintf(
    "%v <%v> has %v replica(s) but PodDisruptionBudget <%v> has minAvailable of %v, only positive integers less than %v are allowed for minAvailable",
    [obj.kind, obj.metadata.name, obj.spec.replicas, pdb.metadata.name, pdb.spec.minAvailable, obj.spec.replicas],
  )
}

violation[{"msg": msg}] {
  input.review.kind.kind != "PodDisruptionBudget"
  obj := input.review.object

  pdb := data.inventory.namespace[obj.metadata.namespace]["policy/v1"].PodDisruptionBudget[_]
  obj.spec.selector.matchLabels == pdb.spec.selector.matchLabels

  not valid_pdb_min_available(obj, pdb)
  msg := sprintf(
    "%v <%v> has %v replica(s) but PodDisruptionBudget <%v> has minAvailable of %v, only positive integers less than %v are allowed for minAvailable",
    [obj.kind, obj.metadata.name, obj.spec.replicas, pdb.metadata.name, pdb.spec.minAvailable, obj.spec.replicas],
  )
}

violation[{"msg": msg}] {
  input.review.kind.kind != "PodDisruptionBudget"
  obj := input.review.object

  pdb := data.inventory.namespace[obj.metadata.namespace]["policy/v1"].PodDisruptionBudget[_]
  obj.spec.selector.matchLabels == pdb.spec.selector.matchLabels

  not valid_pdb_max_unavailable(pdb)
  msg := sprintf(
    "%v <%v> being selected by PodDisruptionBudget <%v>, which has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
    [obj.kind, obj.metadata.name, pdb.metadata.name],
  )
}

valid_pdb_min_available(obj, pdb) {
  # default to -1 if minAvailable is not set so valid_pdb_min_available is always true for objects with >= 0 replicas
  min_available := object.get(pdb.spec, "minAvailable", -1)
  obj.spec.replicas > min_available
}

valid_pdb_max_unavailable(pdb) {
  # default to 1 if maxUnavailable is not set so valid_pdb_max_unavailable always returns true
  max_unavailable := object.get(pdb.spec, "maxUnavailable", 1)
  max_unavailable > 0
}
