package k8spoddisruptionbudget

namespace := "namespace-1"

match_labels := {"matchLabels": {
  "key1": "val1",
  "key2": "val2",
}}

test_input_pdb_0_max_unavailable {
  inp := {"review": input_pdb_max_unavailable(0)}
  results := violation with input as inp
  count(results) == 1
}

test_input_pdb_0_max_unavailable_percent {
  inp := {"review": input_pdb_max_unavailable("0%")}
  results := violation with input as inp
  count(results) == 1
}

test_input_pdb_1_max_unavailable {
  inp := {"review": input_pdb_max_unavailable(1)}
  results := violation with input as inp
  count(results) == 0
}

test_input_deployment_1_replica_pdb_1_min_available {
  inp := {"review": input_deployment(1)}
  inv := inv_pdb_min_available(1)
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_deployment_1_replica_pdb_1_min_available_percent {
  inp := {"review": input_deployment(1)}
  inv := inv_pdb_min_available("100%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_deployment_no_replicas_field {
  # This test handles the case where a deployment doesn't explicitly
  # set the replicas field. Kubernetes defaults this to 1.
  # The policy should handle this gracefully.
  inp := {"review": input_deployment(0)} # Using 0 to trigger creation of a deployment without the replicas field
  inv := inv_pdb_min_available(1)
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_deployment_no_pdb {
  # This test ensures that if a deployment is reviewed but no PDB
  # that selects it exists, no violation is triggered.
  inp := {"review": input_deployment(1)}
  inv := {} # Empty inventory
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_deployment_2_replicas_pdb_1_min_available {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_min_available(1)
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_deployment_2_replicas_pdb_1_min_available_percent {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_min_available("50%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_hpa_1_replica_pdb_1_min_available {
  inp := {"review": input_hpa(1)}
  inv := inv_pdb_min_available_deploy(1, 1)
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_hpa_1_replica_pdb_1_min_available_percent {
  inp := {"review": input_hpa(1)}
  inv := inv_pdb_min_available_deploy(1, "100%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_hpa_1_replica_pdb_1_min_available_percent_half {
  inp := {"review": input_hpa(1)}
  inv := inv_pdb_min_available_deploy(1, "50%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_hpa_1_replica_pdb_1_max_unavailable {
  inp := {"review": input_hpa(1)}
  inv := inv_pdb_max_unavailable_deploy(1, 0)
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_hpa_1_replica_pdb_1_max_unavailable_percent {
  inp := {"review": input_hpa(1)}
  inv := inv_pdb_max_unavailable_deploy(1, "0%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_hpa_2_replica_pdb_1_max_unavailable {
  inp := {"review": input_hpa(2)}
  inv := inv_pdb_max_unavailable_deploy(1, 1)
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_hpa_1_replica_pdb_max_unavailable_percent_rounds_to_zero {
  inp := {"review": input_hpa(1)}
  inv := inv_pdb_max_unavailable_deploy(1, "50%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_hpa_1_replica_pdb_1_max_unavailable_percent_100 {
  inp := {"review": input_hpa(1)}
  inv := inv_pdb_max_unavailable_deploy(1, "100%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_hpa_2_replica_pdb_1_min_available {
  inp := {"review": input_hpa(2)}
  inv := inv_pdb_min_available_deploy(1, 1)
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_hpa_2_replica_pdb_2_min_available {
  inp := {"review": input_hpa(2)}
  inv := inv_pdb_min_available_deploy(1, 2)
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_hpa_3_replica_pdb_3_min_available {
  inp := {"review": input_hpa(3)}
  inv := inv_pdb_min_available_deploy(1, 3)
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_hpa_2_replica_pdb_1_min_available_percent_half_hpa {
  inp := {"review": input_hpa(2)}
  inv := inv_pdb_min_available_deploy(1, "50%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_hpa_2_replica_pdb_1_min_available_percent_quarter {
  inp := {"review": input_hpa(2)}
  inv := inv_pdb_min_available_deploy(1, "75%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_deployment_2_replicas_pdb_1_min_available {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_min_available_deploy(2, 1)
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_deployment_2_replicas_pdb_1_min_available_percent {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_min_available_deploy(2, "50%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_deployment_pdb_0_max_unavailable {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_max_unavailable(0)
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_deployment_pdb_0_max_unavailable_percent {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_max_unavailable("0%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_deployment_pdb_1_max_unavailable {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_max_unavailable(1)
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_deployment_pdb_1_max_unavailable_percent {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_max_unavailable("50%")
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

# Add a new test for deployment with HPA scenario
test_input_deployment_with_hpa_1_replica_pdb_1_min_available {
  inp := {"review": input_deployment(1)}  # deployment has 1 replica
  inv := inv_pdb_min_available_deploy_with_hpa(1, 2, 1)  # HPA has minReplicas=2
  results := violation with input as inp with data.inventory as inv
  count(results) == 0  # Should pass because HPA minReplicas (2) > PDB minAvailable (1)
}

test_input_deployment_with_hpa_1_replica_pdb_2_min_available {
  inp := {"review": input_deployment(1)}  # deployment has 1 replica
  inv := inv_pdb_min_available_deploy_with_hpa(1, 2, 2)  # HPA has minReplicas=2
  results := violation with input as inp with data.inventory as inv
  count(results) == 1  # Should fail because HPA minReplicas (2) == PDB minAvailable (2)
}

# Helper function to create inventory with HPA managing the deployment
inv_pdb_min_available_deploy_with_hpa(deployment_replicas, hpa_min_replicas, min_available) = output {
  pdb = pdb_min_available(min_available)
  dep_obj = deployment(deployment_replicas)
  hpa_obj = hpa(hpa_min_replicas)
  output := {"namespace": {namespace: {
    pdb.apiVersion: {pdb.kind: [pdb]},
    dep_obj.apiVersion: {dep_obj.kind: [dep_obj]},
    hpa_obj.apiVersion: {hpa_obj.kind: [hpa_obj]},
  }}}
}

inv_pdb_max_unavailable_deploy_with_hpa(deployment_replicas, hpa_min_replicas, max_unavailable) = output {
  pdb = pdb_max_unavailable(max_unavailable)
  dep_obj = deployment(deployment_replicas)
  hpa_obj = hpa(hpa_min_replicas)
  output := {"namespace": {namespace: {
    pdb.apiVersion: {pdb.kind: [pdb]},
    dep_obj.apiVersion: {dep_obj.kind: [dep_obj]},
    hpa_obj.apiVersion: {hpa_obj.kind: [hpa_obj]},
  }}}
}

pdb_min_available(min_available) = output {
  output := {
    "apiVersion": "policy/v1",
    "kind": "PodDisruptionBudget",
    "metadata": {
      "name": "pdb-1",
      "namespace": "namespace-1",
    },
    "spec": {
      "selector": match_labels,
      "minAvailable": min_available,
    },
  }
}

pdb_max_unavailable(max_unavailable) = output {
  output := {
    "apiVersion": "policy/v1",
    "kind": "PodDisruptionBudget",
    "metadata": {
      "name": "pdb-1",
      "namespace": "namespace-1",
    },
    "spec": {
      "selector": match_labels,
      "maxUnavailable": max_unavailable,
    },
  }
}

deployment(replicas) = output {
  output := {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "deployment-1",
      "namespace": "namespace-1",
    },
    "spec": {
      "replicas": replicas,
      "selector": match_labels,
    },
  }
}

hpa(min_replicas) = output {
  output := {
    "apiVersion": "autoscaling/v2",
    "kind": "HorizontalPodAutoscaler",
    "metadata": {
      "name": "hpa-1",
      "namespace": "namespace-1",
    },
    "spec": {
      "minReplicas": min_replicas,
      "scaleTargetRef": {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "name": "deployment-1",
      },
    },
  }
}

input_pdb_max_unavailable(max_unavailable) = output {
  output := {
    "kind": {"kind": "PodDisruptionBudget"},
    "object": pdb_max_unavailable(max_unavailable),
  }
}

input_deployment(replicas) = output {
  output := {
    "kind": {"kind": "Deployment"},
    "object": deployment(replicas),
  }
}

input_hpa(min_replicas) = output {
  output := {
    "kind": {"kind": "HorizontalPodAutoscaler"},
    "object": hpa(min_replicas),
  }
}

inventory(obj) = output {
  output := {"namespace": {namespace: {obj.apiVersion: {obj.kind: [obj]}}}}
}

inv_pdb_min_available(min_available) = output {
  pdb = pdb_min_available(min_available)
  output := inventory(pdb)
}

inv_pdb_min_available_deploy(replicas, min_available) = output {
  pdb = pdb_min_available(min_available)
  dep_obj = deployment(replicas)
  output := {"namespace": {namespace: {
    pdb.apiVersion: {pdb.kind: [pdb]},
    dep_obj.apiVersion: {dep_obj.kind: [dep_obj]},
  }}}
}

inv_pdb_max_unavailable_deploy(replicas, max_unavailable) = output {
  pdb = pdb_max_unavailable(max_unavailable)
  dep_obj = deployment(replicas)
  output := {"namespace": {namespace: {
    pdb.apiVersion: {pdb.kind: [pdb]},
    dep_obj.apiVersion: {dep_obj.kind: [dep_obj]},
  }}}
}

inv_pdb_max_unavailable(max_unavailable) = output {
  pdb = pdb_max_unavailable(max_unavailable)
  output := inventory(pdb)
}
