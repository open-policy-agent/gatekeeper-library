package k8sairequiredcontrols

# --- Annotation tests ---

test_annotation_missing {
  inp := {
    "review": input_review_no_annotations,
    "parameters": {
      "requiredAnnotations": [{"key": "ai-controls/audit-logging", "value": "enabled"}],
      "credentialEnvPatterns": [],
    },
  }
  results := violation with input as inp
  count(results) == 1
}

test_annotation_wrong_value {
  inp := {
    "review": input_review_annotation_wrong_value,
    "parameters": {
      "requiredAnnotations": [{"key": "ai-controls/audit-logging", "value": "enabled"}],
      "credentialEnvPatterns": [],
    },
  }
  results := violation with input as inp
  count(results) == 1
}

test_annotation_correct_value_allowed {
  inp := {
    "review": input_review_with_annotation,
    "parameters": {
      "requiredAnnotations": [{"key": "ai-controls/audit-logging", "value": "enabled"}],
      "credentialEnvPatterns": [],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

test_annotation_key_only_any_value_allowed {
  inp := {
    "review": input_review_with_annotation,
    "parameters": {
      "requiredAnnotations": [{"key": "ai-controls/audit-logging", "value": ""}],
      "credentialEnvPatterns": [],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

test_no_required_annotations_no_violation {
  inp := {
    "review": input_review_no_annotations,
    "parameters": {
      "requiredAnnotations": [],
      "credentialEnvPatterns": [],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

# --- Credential env var tests ---

test_credential_plain_value_denied {
  inp := {
    "review": input_review_credential_plain,
    "parameters": {
      "requiredAnnotations": [],
      "credentialEnvPatterns": [".*_KEY$", ".*_TOKEN$", ".*_SECRET$"],
    },
  }
  results := violation with input as inp
  count(results) == 1
}

test_credential_secret_ref_allowed {
  inp := {
    "review": input_review_credential_secretref,
    "parameters": {
      "requiredAnnotations": [],
      "credentialEnvPatterns": [".*_KEY$", ".*_TOKEN$", ".*_SECRET$"],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

test_credential_init_container_denied {
  inp := {
    "review": input_review_credential_init_plain,
    "parameters": {
      "requiredAnnotations": [],
      "credentialEnvPatterns": [".*_KEY$"],
    },
  }
  results := violation with input as inp
  count(results) == 1
}

test_no_credential_patterns_no_violation {
  inp := {
    "review": input_review_credential_plain,
    "parameters": {
      "requiredAnnotations": [],
      "credentialEnvPatterns": [],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

test_full_compliance_no_violations {
  inp := {
    "review": input_review_fully_compliant,
    "parameters": {
      "requiredAnnotations": [{"key": "ai-controls/audit-logging", "value": "enabled"}],
      "credentialEnvPatterns": [".*_KEY$", ".*_TOKEN$"],
    },
  }
  results := violation with input as inp
  count(results) == 0
}

# --- Input fixtures ---

input_review_no_annotations = {
  "object": {
    "metadata": {
      "name": "ai-model-pod",
      "labels": {"workload-type": "ai-model"},
    },
    "spec": {
      "containers": [{"name": "model-server", "image": "registry.example.com/model:v1"}],
    },
  },
}

input_review_annotation_wrong_value = {
  "object": {
    "metadata": {
      "name": "ai-model-pod",
      "annotations": {"ai-controls/audit-logging": "disabled"},
    },
    "spec": {
      "containers": [{"name": "model-server", "image": "registry.example.com/model:v1"}],
    },
  },
}

input_review_with_annotation = {
  "object": {
    "metadata": {
      "name": "ai-model-pod",
      "annotations": {"ai-controls/audit-logging": "enabled"},
    },
    "spec": {
      "containers": [{"name": "model-server", "image": "registry.example.com/model:v1"}],
    },
  },
}

input_review_credential_plain = {
  "object": {
    "metadata": {"name": "ai-model-pod"},
    "spec": {
      "containers": [{
        "name": "model-server",
        "image": "registry.example.com/model:v1",
        "env": [{"name": "OPENAI_API_KEY", "value": "sk-plaintextabc123"}],
      }],
    },
  },
}

input_review_credential_secretref = {
  "object": {
    "metadata": {"name": "ai-model-pod"},
    "spec": {
      "containers": [{
        "name": "model-server",
        "image": "registry.example.com/model:v1",
        "env": [{
          "name": "OPENAI_API_KEY",
          "valueFrom": {"secretKeyRef": {"name": "openai-creds", "key": "api-key"}},
        }],
      }],
    },
  },
}

input_review_credential_init_plain = {
  "object": {
    "metadata": {"name": "ai-model-pod"},
    "spec": {
      "containers": [{"name": "model-server", "image": "registry.example.com/model:v1"}],
      "initContainers": [{
        "name": "init-loader",
        "image": "registry.example.com/init:v1",
        "env": [{"name": "LOADER_API_KEY", "value": "sk-plaintextinit"}],
      }],
    },
  },
}

input_review_fully_compliant = {
  "object": {
    "metadata": {
      "name": "ai-model-pod",
      "annotations": {"ai-controls/audit-logging": "enabled"},
      "labels": {"workload-type": "ai-model"},
    },
    "spec": {
      "containers": [{
        "name": "model-server",
        "image": "registry.example.com/model:v1@sha256:abc123def456",
        "env": [{
          "name": "MODEL_API_KEY",
          "valueFrom": {"secretKeyRef": {"name": "model-creds", "key": "api-key"}},
        }],
      }],
    },
  },
}
