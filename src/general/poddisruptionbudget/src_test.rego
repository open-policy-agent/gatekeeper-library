package k8spoddisruptionbudget

namespace := "namespace-1"

match_labels := {"matchLabels": {
  "key1": "val1",
  "key2": "val2",
}}

labels := object.union(match_labels["matchLabels"], {"key3": "val3"})

test_input_pdb_0_max_unavailable {
  inp := {"review": input_pdb_max_unavailable(0)}
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

test_input_deployment_2_replicas_pdb_1_min_available {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_min_available(1)
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_deployment_pdb_0_max_unavailable {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_max_unavailable(0)
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
}

test_input_deployment_pdb_1_max_unavailable {
  inp := {"review": input_deployment(2)}
  inv := inv_pdb_max_unavailable(1)
  results := violation with input as inp with data.inventory as inv
  count(results) == 0
}

test_input_deployment_pdb_matches_template_labels_not_selector {
  inp := {"review": input_deployment_with_selector(1, match_labels["matchLabels"])}
  inv := inv_pdb_min_available_with_selector(1, {"matchLabels": {"key3": "val3"}})
  results := violation with input as inp with data.inventory as inv
  count(results) == 1
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

pdb_min_available_with_selector(min_available, selector) = output {
  output := {
    "apiVersion": "policy/v1",
    "kind": "PodDisruptionBudget",
    "metadata": {
      "name": "pdb-1",
      "namespace": "namespace-1",
    },
    "spec": {
      "selector": selector,
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

deployment_with_selector(replicas, selector) = output {
  output := {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "deployment-1",
      "namespace": "namespace-1",
    },
    "spec": {
      "replicas": replicas,
      "selector": {
        "matchLabels": selector,
      },
      "template": {
        "metadata": {
          "labels": labels,
        }
      }
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
      "template": {
        "metadata": {
          "labels": labels,
        }
      }
    },
  }
}

input_deployment_with_selector(replicas, selector) = output {
  output := {
    "kind": {"kind": "Deployment"},
    "object": deployment_with_selector(replicas, selector),
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

inventory(obj) = output {
  output := {"namespace": {namespace: {obj.apiVersion: {obj.kind: [obj]}}}}
}

inv_pdb_min_available(min_available) = output {
  pdb = pdb_min_available(min_available)
  output := inventory(pdb)
}

inv_pdb_min_available_with_selector(min_available, selector) = output {
  pdb = pdb_min_available_with_selector(min_available, selector)
  output := inventory(pdb)
}

inv_pdb_max_unavailable(max_unavailable) = output {
  pdb = pdb_max_unavailable(max_unavailable)
  output := inventory(pdb)
}
