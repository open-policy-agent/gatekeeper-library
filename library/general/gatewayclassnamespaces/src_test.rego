package gatewayclassnamespaces

test_no_data {
    input := {"review": review(gateway("my-gateway", "prod", "external-lb"))}
    results := violation with input as input
    count(results) == 1
}

test_valid {
    input := {
      "review": review(gateway("my-gateway", "prod", "external-lb")), 
      "parameters": {"gatewayClasses": [{"name": "external-lb", "namespaces": ["prod"]}]}
    }
    trace(sprintf("Test: %v", [json.marshal(input)]))
    results := violation with input as input
    count(results) == 0
}

test_no_allowed_namespaces {
    input := {
      "review": review(gateway("my-gateway", "prod", "external-lb")), 
      "parameters": {"gatewayClasses": [{"name": "external-lb", "namespaces": []}]}
    }
    results := violation with input as input
    count(results) == 1
}


review(gw) = output {
  output = {
    "kind": {
      "kind": "Gateway",
      "version": "v1alpha1",
      "group": "networking.x-k8s.io",
    },
    "namespace": gw.metadata.namespace,
    "name": gw.metadata.name,
    "object": gw,
  }
}

gateway(name, ns, gcName) = out {
  out = {
    "kind": "Gateway",
    "apiVersion": "networking.x-k8s.io/v1alpha1",
    "metadata": {
      "name": name,
      "namespace": ns,
    },
    "spec": {
      "gatewayClassName": gcName,
    },
  }
}
