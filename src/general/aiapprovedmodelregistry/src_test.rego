package k8saiapprovedmodelregistry

# --- Approved registry tests ---

test_approved_registry_allowed {
  inp := {
    "review": input_review_approved,
    "parameters": {
      "approvedRegistries": ["model-registry.example.com/", "ghcr.io/myorg/"],
      "requireDigestPin": false,
    },
  }
  results := violation with input as inp
  count(results) == 0
}

test_unapproved_registry_denied {
  inp := {
    "review": input_review_unapproved,
    "parameters": {
      "approvedRegistries": ["model-registry.example.com/"],
      "requireDigestPin": false,
    },
  }
  results := violation with input as inp
  count(results) == 1
}

test_mixed_containers_one_denied {
  inp := {
    "review": input_review_mixed,
    "parameters": {
      "approvedRegistries": ["model-registry.example.com/"],
      "requireDigestPin": false,
    },
  }
  results := violation with input as inp
  count(results) == 1
}

test_init_container_unapproved_denied {
  inp := {
    "review": input_review_init_unapproved,
    "parameters": {
      "approvedRegistries": ["model-registry.example.com/"],
      "requireDigestPin": false,
    },
  }
  results := violation with input as inp
  count(results) == 1
}

# --- Digest pin tests ---

test_digest_pinned_allowed {
  inp := {
    "review": input_review_digest_pinned,
    "parameters": {
      "approvedRegistries": ["model-registry.example.com/"],
      "requireDigestPin": true,
    },
  }
  results := violation with input as inp
  count(results) == 0
}

test_digest_not_pinned_denied {
  inp := {
    "review": input_review_approved,
    "parameters": {
      "approvedRegistries": ["model-registry.example.com/"],
      "requireDigestPin": true,
    },
  }
  results := violation with input as inp
  count(results) == 1
}

test_digest_pin_disabled_no_violation {
  inp := {
    "review": input_review_approved,
    "parameters": {
      "approvedRegistries": ["model-registry.example.com/"],
      "requireDigestPin": false,
    },
  }
  results := violation with input as inp
  count(results) == 0
}

# --- Input fixtures ---

input_review_approved = {
  "object": {
    "metadata": {"name": "ai-model-pod"},
    "spec": {
      "containers": [{"name": "model-server", "image": "model-registry.example.com/llama3:v2.1"}],
    },
  },
}

input_review_unapproved = {
  "object": {
    "metadata": {"name": "ai-model-pod"},
    "spec": {
      "containers": [{"name": "model-server", "image": "docker.io/library/ubuntu:latest"}],
    },
  },
}

input_review_mixed = {
  "object": {
    "metadata": {"name": "ai-model-pod"},
    "spec": {
      "containers": [
        {"name": "model-server", "image": "model-registry.example.com/llama3:v2.1"},
        {"name": "sidecar", "image": "docker.io/library/nginx:latest"},
      ],
    },
  },
}

input_review_init_unapproved = {
  "object": {
    "metadata": {"name": "ai-model-pod"},
    "spec": {
      "containers": [{"name": "model-server", "image": "model-registry.example.com/llama3:v2.1"}],
      "initContainers": [{"name": "downloader", "image": "docker.io/library/alpine:3"}],
    },
  },
}

input_review_digest_pinned = {
  "object": {
    "metadata": {"name": "ai-model-pod"},
    "spec": {
      "containers": [{
        "name": "model-server",
        "image": "model-registry.example.com/llama3:v2.1@sha256:abc123def456789",
      }],
    },
  },
}
