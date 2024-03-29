package k8suniqueserviceselector

test_no_data {
    inp := {"review": review(service("my-service", "prod", {"a": "b"}))}
    results := violation with input as inp
    count(results) == 0
}
test_identical {
    inp := {"review": review(service("my-service", "prod", {"a": "b"}))}
    inv := tmp_data([service("my-service", "prod", {"a": "b"})])
            trace(sprintf("%v", [inv]))

    results := violation with input as inp with data.inventory as inv
                trace(sprintf("%v", [results]))

    count(results) == 0
}
test_collision {
    inp := {"review": review(service("my-service", "prod", {"a": "b"}))}
    inv := tmp_data([service("my-service", "prod2", {"a": "b"})])
    results := violation with input as inp with data.inventory as inv
    count(results) == 1
}
test_collision_with_multiple {
    inp := {"review": review(service("my-service", "prod", {"a": "b"}))}
    inv := tmp_data([service("my-service", "prod2", {"a": "b"}), service("my-service", "prod3", {"a": "b"})])
    results := violation with input as inp with data.inventory as inv
    count(results) == 2
}
test_no_collision {
    inp := {"review": review(service("my-service", "prod", {"a": "b"}))}
    inv := tmp_data([service("my-service", "prod2", {"a": "c"})])
    results := violation with input as inp with data.inventory as inv
    count(results) == 0
}
test_no_collision_with_multiple {
    inp := {"review": review(service("my-service", "prod", {"a": "b"}))}
    inv := tmp_data([service("my-service", "prod2", {"a": "b2"}), service("my-service", "prod3", {"a": "b2"})])
    results := violation with input as inp with data.inventory as inv
    count(results) == 0
}
test_compound_selector_collision {
    inp := {"review": review(service("my-service", "prod", {"r": "d", "a": "b"}))}
    inv := tmp_data([service("my-service", "prod2", {"a": "b", "r": "d"})])
    results := violation with input as inp with data.inventory as inv
    count(results) == 1
}

test_no_service_selector {
    inp := {"review": review(service_without_selector("kubernetes", "default"))}
    inv := data_networkpolicy("default")
    results := violation with input as inp with data.inventory as inv
    count(results) == 0
}


review(srv) = output {
  output = {
    "kind": {
      "kind": "Service",
      "version": "v1",
      "group": "",
    },
    "namespace": srv.metadata.namespace,
    "name": srv.metadata.name,
    "object": srv,
  }
}

service_without_selector(name, ns) = out {
  out = {
    "kind": "Service",
    "apiVersion": "v1",
    "metadata": {
      "name": name,
      "namespace": ns,
    },
    "spec": {
        "clusterIP": "10.43.0.1",
        "clusterIPs": [
            "10.43.0.1"
        ],
        "ports": [
            {
                "name": "https",
                "port": 443,
                "protocol": "TCP",
                "targetPort": 6443
            }
        ],
        "sessionAffinity": "None",
        "type": "ClusterIP"
    }
  }
}

service(name, ns, selector) = out {
  out = {
    "kind": "Service",
    "apiVersion": "v1",
    "metadata": {
      "name": name,
      "namespace": ns,
    },
    "spec": {"selector": selector}
  }
}

data_networkpolicy(ns) = out {
  out = {
    "namespace": {
      ns: {
        "v1": {
          "NetworkPolicy": {
            "default-network-policy": {
              "apiVersion": "networking.k8s.io/v1",
              "kind": "NetworkPolicy",
              "metadata": {
                "name": "default-network-policy",
                "namespace": ns
              },
              "spec": {
                "ingress": [
                  {
                    "from": [
                      {
                        "podSelector": {}
                      }
                    ]
                  }
                ],
                "podSelector": {},
                "policyTypes": [
                  "Ingress"
                ]
              }
            }
          }
        }
      }
    }
  }
}

tmp_data(services) = out {
  namespaces := {ns | ns = services[_].metadata.namespace}
  out = {
    "namespace": {
      ns: {
        "v1": {
          "Service": flatten_by_name(services, ns)
        }
      } | ns := namespaces[_]
    }
  }
}

flatten_by_name(services, ns) = out {
  out = {o.metadata.name: o | o = services[_]; o.metadata.namespace = ns}
}
