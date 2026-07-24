package k8sreplicalimits

test_input_empty {
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

