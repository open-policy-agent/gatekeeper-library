package k8shorizontalpodautoscaler

namespace := "namespace-1"

valid_scale_target_ref := {
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "name": "deployment-1"
}

invalid_scale_target_ref := {
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "name": "deployment-invalid"
}

deployment := {
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {
    "name": "deployment-1",
    "namespace": "namespace-1",
  },
  "spec": {
    "replicas": 1,
  }
}

test_input_hpa_min_replicas_outside_range {
  inp := {"review": input_hpa(2,5,valid_scale_target_ref), "parameters": input_parameters_valid_range}
  results := violation with input as inp
  count(results) == 1
}

test_input_hpa_max_replicas_outside_range {
  inp := {"review": input_hpa(4,7,valid_scale_target_ref), "parameters": input_parameters_valid_range}
  results := violation with input as inp
  count(results) == 1
}

test_input_hpa_replicas_within_range {
  inp := {"review": input_hpa(4,5,valid_scale_target_ref), "parameters": input_parameters_valid_range}
  results := violation with input as inp
  count(results) == 0
}

test_input_hpa_replicas_equal_range {
  inp := {"review": input_hpa(3,6,valid_scale_target_ref), "parameters": input_parameters_valid_range}
  results := violation with input as inp
  count(results) == 0
}

test_input_hpa_replicas_below_min_spread {
  inp := {"review": input_hpa(3,4,valid_scale_target_ref), "parameters": input_parameters_min_spread}
  results := violation with input as inp
  count(results) == 1
}

test_input_hpa_replicas_above_min_spread {
  inp := {"review": input_hpa(3,6,valid_scale_target_ref), "parameters": input_parameters_min_spread}
  results := violation with input as inp
  count(results) == 0
}

test_input_hpa_replicas_equal_min_spread {
  inp := {"review": input_hpa(4,6,valid_scale_target_ref), "parameters": input_parameters_min_spread}
  results := violation with input as inp
  count(results) == 0
}

test_input_hpa_invalid_scale_target{
  inp := {"review": input_hpa(3,6,invalid_scale_target_ref), "parameters": input_parameters_enforce_scale_target_ref}
  inv := inv_deployment(deployment)
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_hpa_valid_scale_target{
  inp := {"review": input_hpa(3,6,valid_scale_target_ref), "parameters": input_parameters_enforce_scale_target_ref}
  inv := inv_deployment(deployment)
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

hpa(min_replicas, max_replicas, scale_target_ref) = output {
  output := {
    "apiVersion": "autoscaling/v1",
    "kind": "HorizontalPodAutoscaler",
    "metadata": {
      "name": "hpa-1",
      "namespace": "namespace-1",
    },
    "spec": {
      "scaleTargetRef": scale_target_ref,
      "minReplicas": min_replicas,
      "maxReplicas": max_replicas,
    },
  }
}

input_hpa(min_replicas, max_replicas, scale_target_ref) = output {
  output := {
    "kind": {"kind": "HorizontalPodAutoscaler"},
    "object": hpa(min_replicas, max_replicas, scale_target_ref),
  }
}

inventory(obj) = output {
  output := {"namespace": {namespace: {obj.apiVersion: {obj.kind: {obj.metadata.name: obj}}}}}
}

inv_deployment(deploy) = output {
  output := inventory(deploy)
}

input_parameters_valid_range = {
    "ranges": [
    {
        "min_replicas": 3,
        "max_replicas": 6
    }]
}

input_parameters_min_spread = {
    "minimumReplicaSpread": 2
}

input_parameters_enforce_scale_target_ref = {
    "enforceScaleTargetRef": true
}
