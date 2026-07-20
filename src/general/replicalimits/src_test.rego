package k8sreplicalimits

test_input_empty {
    # Missing ranges means the policy cannot evaluate a limit.
    # (empty review object; no parameters.ranges)
    inp := { "review": empty, "parameters": {}}
    results := violation with input as inp
    count(results) == 0
}

test_input_within_required_replicas {
    inp := { "review": review(6), "parameters": input_parameters_valid_range}
    results := violation with input as inp
    count(results) == 0
}

test_input_exact_required_replicas_min {
    inp := { "review": review(5), "parameters": input_parameters_valid_range}
    results := violation with input as inp
    count(results) == 0
}

test_input_exact_required_replicas_max {
    inp := { "review": review(35), "parameters": input_parameters_valid_range}
    results := violation with input as inp
    count(results) == 0
}

test_input_not_enough_required_replicas {
    inp := { "review": review(1), "parameters": input_parameters_valid_range}
    results := violation with input as inp
    count(results) == 1
}

test_input_too_many_replicas {
    inp := { "review": review(100), "parameters": input_parameters_valid_range}
    results := violation with input as inp
    count(results) == 1
}

test_input_zero_replicas {
    inp := { "review": review(0), "parameters": input_parameters_zero_range}
    results := violation with input as inp
    count(results) == 0
}

test_input_scale_empty_spec_zero_allowed {
    # kubectl scale --replicas=0 can produce a Scale object with empty/missing
    # spec.replicas; missing must be treated as 0 when zero is in range.
    inp := { "review": scale_empty_spec, "parameters": input_parameters_zero_range}
    results := violation with input as inp
    count(results) == 0
}

test_input_scale_empty_spec_zero_disallowed {
    inp := { "review": scale_empty_spec, "parameters": input_parameters_valid_range}
    results := violation with input as inp
    count(results) == 1
}

test_input_scale_replicas_within_range {
    inp := { "review": scale_review(10), "parameters": input_parameters_valid_range}
    results := violation with input as inp
    count(results) == 0
}

test_input_scale_replicas_outside_range {
    inp := { "review": scale_review(1), "parameters": input_parameters_valid_range}
    results := violation with input as inp
    count(results) == 1
}

empty = {
  "object": {
    "metadata": {
      "name": "nginx"
    },
  }
}

review(replicas) = output {
  output = {
    "kind": {
      "kind": "Deployment",
      "version": "v1",
      "group": "apps",
    },
    "object": {
    "metadata": {
        "name": "nginx"
    },
      "spec": {
        "replicas": replicas,
      },
    }
  }
}

scale_review(replicas) = output {
  output = {
    "kind": {
      "kind": "Scale",
      "version": "v1",
      "group": "autoscaling",
    },
    "object": {
      "metadata": {
        "name": "nginx"
      },
      "spec": {
        "replicas": replicas,
      },
    }
  }
}

scale_empty_spec = {
  "kind": {
    "kind": "Scale",
    "version": "v1",
    "group": "autoscaling",
  },
  "object": {
    "metadata": {
      "name": "nginx"
    },
    "spec": {}
  }
}

input_parameters_valid_range = {
    "ranges": [
    {
        "min_replicas": 5,
        "max_replicas": 35
    }]
}

input_parameters_zero_range = {
    "ranges": [
    {
        "min_replicas": 0,
        "max_replicas": 0
    }]
}
