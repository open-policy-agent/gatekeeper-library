package K8sBlockWildcardIngress

test_input_ingress_allowed_host {
  input := { "review": input_review(input_ingress_allowed_host) }
  results := violation with input as input
  count(results) == 0
}

test_input_ingress_disallowed_wildcard_host {
  input := { "review": input_review(input_ingress_disallowed_wildcard_host) }
  results := violation with input as input
  count(results) == 1
}

test_input_ingress_disallowed_empty_host {
  input := { "review": input_review(input_ingress_disallowed_empty_host) }
  results := violation with input as input
  count(results) == 1
}

test_input_ingress_disallowed_empty_host {
  input := { "review": input_review(input_ingress_disallowed_empty_host) }
  results := violation with input as input
  count(results) == 1
}

test_input_ingress_no_rules {
  input := { "review": input_review(input_ingress_no_rules) }
  results := violation with input as input
  count(results) == 1
}

input_review(rules) = output {
  output = {
    "kind": {
      "kind": "Ingress"
    },
    "object": {
      "spec": {
        "rules": rules
      }
    }
  }
}

input_ingress_allowed_host = [{
  "host": "foo.bar.com"
}]

input_ingress_disallowed_wildcard_host = [{
  "host": "foo.bar.com"
}, {
  "host": "*.foo.com"
}]

input_ingress_disallowed_empty_host = [{
  "host": ""
}]

input_ingress_no_rules = [{}]
