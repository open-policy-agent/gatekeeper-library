package k8shttpsonly

test_http_disallowed {
    inp := {"review": review_ingress(annotation("false"), tls)}
    results := violation with input as inp
    count(results) == 0
}
test_boolean_annotation {
    inp := {"review": review_ingress(annotation(false), tls)}
    results := violation with input as inp
    count(results) == 1
}
test_true_annotation {
    inp := {"review": review_ingress(annotation("true"), tls)}
    results := violation with input as inp
    count(results) == 1
}
test_missing_annotation {
    inp := {"review": review_ingress({}, tls)}
    results := violation with input as inp
    count(results) == 1
}
test_empty_tls {
    inp := {"review": review_ingress({}, empty_tls)}
    results := violation with input as inp
    count(results) == 1
}
test_missing_tls {
    inp := {"review": review_ingress(annotation("false"), {})}
    results := violation with input as inp
    count(results) == 1
}
test_missing_all {
    inp := {"review": review_ingress({}, {})}
    results := violation with input as inp
    count(results) == 1
}
test_tls_optional_missing_tls {
    inp := {"review": review_ingress(annotation("false"), {}), "parameters": {"tlsOptional": true}}
    results := violation with input as inp
    count(results) == 0
}
test_tls_optional_empty_tls {
    inp := {"review": review_ingress(annotation("false"), empty_tls), "parameters": {"tlsOptional": true}}
    results := violation with input as inp
    count(results) == 0
}
test_tls_optional_with_tls {
    inp := {"review": review_ingress(annotation("false"), tls), "parameters": {"tlsOptional": true}}
    results := violation with input as inp
    count(results) == 0
}
test_tls_optional_true_annotation {
    inp := {"review": review_ingress(annotation("true"), {}), "parameters": {"tlsOptional": true}}
    results := violation with input as inp
    count(results) == 1
}
test_tls_optional_missing_annotation {
    inp := {"review": review_ingress({}, {}), "parameters": {"tlsOptional": true}}
    results := violation with input as inp
    count(results) == 1
}


review_ingress(annotationVal, tlsVal) = out {
  out = {
    "object": {
      "kind": "Ingress",
      "apiVersion": "extensions/v1beta1",
      "metadata": {
        "name": "my-ingress",
        "annotations": annotationVal
      },
      "spec": tlsVal
    }
  }
}

annotation(val) = out {
  out = {
    "kubernetes.io/ingress.allow-http": val
  }
}

empty_tls = {
  "tls": []
}

tls = {
  "tls": [{"secretName": "secret-cert"}]
}
