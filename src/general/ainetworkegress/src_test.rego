package k8sainetworkegress

# --- hostNetwork tests ---

test_host_network_true_denied {
  inp := {
    "review": input_review_host_network_true,
    "parameters": {
      "blockHostNetwork": true,
      "requiredEgressLabels": [],
    },
  }
  results := violation with input as inp
  count(results) == 1
}

test_host_network_false_allowed {
  inp := {
    "review": input_review_host_network_false,
    "parameters": {
      "blockHostNetwork": true,
      "requiredEgressLabels": [],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

test_host_network_block_disabled_no_violation {
  inp := {
    "review": input_review_host_network_true,
    "parameters": {
      "blockHostNetwork": false,
      "requiredEgressLabels": [],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

# --- Egress label tests ---

test_missing_egress_label_denied {
  inp := {
    "review": input_review_no_labels,
    "parameters": {
      "blockHostNetwork": false,
      "requiredEgressLabels": [{"key": "network-policy/ai-egress", "value": "enforced"}],
    },
  }
  results := violation with input as inp
  count(results) == 1
}

test_egress_label_wrong_value_denied {
  inp := {
    "review": input_review_wrong_label_value,
    "parameters": {
      "blockHostNetwork": false,
      "requiredEgressLabels": [{"key": "network-policy/ai-egress", "value": "enforced"}],
    },
  }
  results := violation with input as inp
  count(results) == 1
}

test_egress_label_correct_allowed {
  inp := {
    "review": input_review_correct_label,
    "parameters": {
      "blockHostNetwork": false,
      "requiredEgressLabels": [{"key": "network-policy/ai-egress", "value": "enforced"}],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

test_egress_label_key_only_allowed {
  inp := {
    "review": input_review_correct_label,
    "parameters": {
      "blockHostNetwork": false,
      "requiredEgressLabels": [{"key": "network-policy/ai-egress", "value": ""}],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

test_empty_required_labels_no_violation {
  inp := {
    "review": input_review_no_labels,
    "parameters": {
      "blockHostNetwork": false,
      "requiredEgressLabels": [],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

test_full_compliance_no_violations {
  inp := {
    "review": input_review_fully_compliant,
    "parameters": {
      "blockHostNetwork": true,
      "requiredEgressLabels": [{"key": "network-policy/ai-egress", "value": "enforced"}],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

# --- Input fixtures ---

input_review_host_network_true = {
  "object": {
    "metadata": {"name": "ai-model-pod", "labels": {"workload-type": "ai-model"}},
    "spec": {
      "hostNetwork": true,
      "containers": [{"name": "model-server", "image": "registry.example.com/model:v1"}],
    },
  },
}

input_review_host_network_false = {
  "object": {
    "metadata": {"name": "ai-model-pod"},
    "spec": {
      "hostNetwork": false,
      "containers": [{"name": "model-server", "image": "registry.example.com/model:v1"}],
    },
  },
}

input_review_no_labels = {
  "object": {
    "metadata": {"name": "ai-model-pod"},
    "spec": {
      "containers": [{"name": "model-server", "image": "registry.example.com/model:v1"}],
    },
  },
}

input_review_wrong_label_value = {
  "object": {
    "metadata": {
      "name": "ai-model-pod",
      "labels": {"network-policy/ai-egress": "disabled"},
    },
    "spec": {
      "containers": [{"name": "model-server", "image": "registry.example.com/model:v1"}],
    },
  },
}

input_review_correct_label = {
  "object": {
    "metadata": {
      "name": "ai-model-pod",
      "labels": {"network-policy/ai-egress": "enforced"},
    },
    "spec": {
      "containers": [{"name": "model-server", "image": "registry.example.com/model:v1"}],
    },
  },
}

input_review_fully_compliant = {
  "object": {
    "metadata": {
      "name": "ai-model-pod",
      "labels": {
        "workload-type": "ai-model",
        "network-policy/ai-egress": "enforced",
      },
    },
    "spec": {
      "hostNetwork": false,
      "containers": [{"name": "model-server", "image": "registry.example.com/model:v1"}],
    },
  },
}
