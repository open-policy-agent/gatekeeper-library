package k8spoddisruptionbudget

import future.keywords

# Helper function to get the workload object
# If the input is an HPA, return the referenced workload
# Otherwise, return the input object itself
get_workload(obj) = workload if {
  obj.kind == "HorizontalPodAutoscaler"
  workload := data.inventory.namespace[obj.metadata.namespace][obj.spec.scaleTargetRef.apiVersion][obj.spec.scaleTargetRef.kind][_]
  workload.metadata.name == obj.spec.scaleTargetRef.name
} else = obj

# Helper function to get the object that should be used for replica counting
# If we're reviewing an HPA, use it directly
# If we're reviewing a workload, check if there's an HPA managing it
get_replica_source(obj, workload) = obj if {
  obj.kind == "HorizontalPodAutoscaler"
} else = hpa if {
  hpa := data.inventory.namespace[workload.metadata.namespace]["autoscaling/v2"].HorizontalPodAutoscaler[_]
  hpa.spec.scaleTargetRef.kind == workload.kind
  hpa.spec.scaleTargetRef.name == workload.metadata.name
} else = workload

get_replicas(obj) = obj.spec.minReplicas if {
  obj.kind == "HorizontalPodAutoscaler"
} else = obj.spec.replicas

violation[{"msg": msg}] {
  input.review.kind.kind == "PodDisruptionBudget"
  pdb := input.review.object

  not valid_pdb_max_unavailable(pdb, pdb)
  msg := sprintf(
    "PodDisruptionBudget <%v> has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
    [pdb.metadata.name],
  )
}

violation[{"msg": msg}] {
  obj := input.review.object
  workload := get_workload(obj)
  replica_source := get_replica_source(obj, workload)

  pdb := data.inventory.namespace[workload.metadata.namespace]["policy/v1"].PodDisruptionBudget[_]

  matchLabels := { [label, value] | some label; value := pdb.spec.selector.matchLabels[label] }
  labels := { [label, value] | some label; value := workload.spec.selector.matchLabels[label] }
  count(matchLabels - labels) == 0

  not valid_pdb_max_unavailable(replica_source, pdb)

  # Build appropriate message based on what was reviewed
  msg := build_max_unavailable_msg(obj, workload, replica_source, pdb)
}

violation[{"msg": msg}] {
  obj := input.review.object
  workload := get_workload(obj)
  replica_source := get_replica_source(obj, workload)

  pdb := data.inventory.namespace[workload.metadata.namespace]["policy/v1"].PodDisruptionBudget[_]

  matchLabels := { [label, value] | some label; value := pdb.spec.selector.matchLabels[label] }
  labels := { [label, value] | some label; value := workload.spec.selector.matchLabels[label] }
  count(matchLabels - labels) == 0

  not valid_pdb_min_available(replica_source, pdb)

  # Build appropriate message based on what was reviewed
  msg := build_min_available_msg(obj, workload, replica_source, pdb)
}

# Helper functions to build appropriate error messages
build_max_unavailable_msg(obj, workload, replica_source, pdb) = msg if {
  obj.kind == "HorizontalPodAutoscaler"
  msg := sprintf(
    "%v <%v> is managed by HPA <%v> and selected by PDB <%v>, which would prevent any pods from being drained. HPA minReplicas is %v and PDB maxUnavailable is %v",
    [workload.kind, workload.metadata.name, obj.metadata.name, pdb.metadata.name, obj.spec.minReplicas, pdb.spec.maxUnavailable],
  )
}

build_max_unavailable_msg(obj, workload, replica_source, pdb) = msg if {
  obj.kind != "HorizontalPodAutoscaler"
  replica_source.kind == "HorizontalPodAutoscaler"
  msg := sprintf(
    "%v <%v> is managed by HPA <%v> and selected by PDB <%v>, which would prevent any pods from being drained. HPA minReplicas is %v and PDB maxUnavailable is %v",
    [obj.kind, obj.metadata.name, replica_source.metadata.name, pdb.metadata.name, replica_source.spec.minReplicas, pdb.spec.maxUnavailable],
  )
}

build_max_unavailable_msg(obj, workload, replica_source, pdb) = msg if {
  obj.kind != "HorizontalPodAutoscaler"
  replica_source.kind != "HorizontalPodAutoscaler"
  msg := sprintf(
    "%v <%v> has been selected by PodDisruptionBudget <%v> but has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
    [obj.kind, obj.metadata.name, pdb.metadata.name],
  )
}

build_min_available_msg(obj, workload, replica_source, pdb) = msg if {
  obj.kind == "HorizontalPodAutoscaler"
  msg := sprintf(
    "%v <%v> is managed by HPA <%v> and selected by PDB <%v>, which would prevent any pods from being drained. HPA minReplicas is %v and PDB minAvailable is %v",
    [workload.kind, workload.metadata.name, obj.metadata.name, pdb.metadata.name, obj.spec.minReplicas, pdb.spec.minAvailable],
  )
}

build_min_available_msg(obj, workload, replica_source, pdb) = msg if {
  obj.kind != "HorizontalPodAutoscaler"
  replica_source.kind == "HorizontalPodAutoscaler"
  msg := sprintf(
    "%v <%v> is managed by HPA <%v> and selected by PDB <%v>, which would prevent any pods from being drained. HPA minReplicas is %v and PDB minAvailable is %v",
    [obj.kind, obj.metadata.name, replica_source.metadata.name, pdb.metadata.name, replica_source.spec.minReplicas, pdb.spec.minAvailable],
  )
}

build_min_available_msg(obj, workload, replica_source, pdb) = msg if {
  obj.kind != "HorizontalPodAutoscaler"
  replica_source.kind != "HorizontalPodAutoscaler"
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
    new := ceil(get_replicas(obj) * per)
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
    get_replicas(obj) > min_available(obj, pdb)
}

max_unavailable(obj, pdb) = new if {
  # if its a percentage, it will return the number of pods that need
  # to be available rounded down (that's how Kubernetes calculates it).
  # if its a number, return that number, if unset return default of 1
    endswith(pdb.spec.maxUnavailable, "%")

    # convert % to a number, if this is 50%, then 50/100 = 0.5
    per := to_number(replace(pdb.spec.maxUnavailable, "%", "")) / 100

    # round down to the nearest integer based on replicas
    # if replicas is 3, then 3 * 0.5 = 1.5, floor(1.5) = 1
    new := floor(get_replicas(obj) * per)
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
