package k8srequiredprobes

test_one_ctr_no_violations {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest","readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 0
}

test_one_ctr_readiness_violation {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_one_ctr_liveness_violation {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_one_ctr_all_violations {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest"}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_no_violations {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest","readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest","readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 0
}

test_two_ctrs_all_violations_in_both {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest"},
                                {"name": "my-container2","image": "my-image:latest"}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 4
}

test_two_ctrs_all_violations_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest"},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_all_violations_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest"}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_readiness_violation_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest","readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_two_ctrs_readiness_violation_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}},
                                {"name": "my-container2","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_two_ctrs_readiness_violation_in_both {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_liveness_violation_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_two_ctrs_liveness_violation_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_two_ctrs_liveness_violation_in_both {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":8080}}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_readiness_in_one_liveness_in_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest","readinessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_liveness_in_one_readiness_in_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_readiness_violation_in_ctr_one_all_violations_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest"}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 3
}

test_two_ctrs_liveness_violation_in_ctr_one_all_violations_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest"}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 3
}

test_two_ctrs_readiness_violation_in_ctr_two_all_violations_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest"},
                                {"name": "my-container2","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 3
}

test_two_ctrs_liveness_violation_in_ctr_two_all_violations_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest"},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 3
}

test_one_ctr_empty_readiness_violation {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_one_ctr_empty_liveness_violation {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_one_ctr_empty_probes_violations {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_empty_probes_violation_in_both {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 4
}

test_two_ctrs_empty_probes_violation_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_empty_probes_violation_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_empty_readiness_violation_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}}, "readinessProbe": {}},
                                {"name": "my-container2","image": "my-image:latest","readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_two_ctrs_empty_readiness_violation_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_two_ctrs_empty_readiness_violation_in_both {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_empty_liveness_violation_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_two_ctrs_empty_liveness_violation_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_two_ctrs_empty_liveness_violation_in_both {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_empty_readiness_in_ctr_one_empty_liveness_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe":{}, "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_empty_liveness_in_one_empty_readiness_in_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_empty_readiness_in_ctr_one_both_empty_probes_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 3
}

test_two_ctrs_empty_liveness_in_ctr_one_both_empty_probes_in_ctr_two {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 3
}

test_two_ctrs_empty_readiness_in_ctr_two_both_empty_probes_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 3
}

test_two_ctrs_empty_liveness_in_ctr_two_both_empty_probes_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 3
}

test_one_ctr_readiness_violation_with_svc_port_name {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "ports": [{ "name": "http", "containerPort": "8080"}], "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters_only_svc}
    inv := inv_svc({"app.kubernetes.io/name": "test"}, [{ "name": "name-of-service-port", "port": "80", "targetPort": "http"}])
    results := violation with input as input with data.inventory as inv
    count(results) == 1
}

test_one_ctr_readiness_violation_with_svc_port_num {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "ports": [{ "name": "http", "containerPort": "8080"}], "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters_only_svc}
    inv := inv_svc({"app.kubernetes.io/name": "test"}, [{ "name": "name-of-service-port", "port": "80", "targetPort": "8080"}])
    results := violation with input as input with data.inventory as inv
    count(results) == 1
}

test_one_ctr_readiness_violation_with_svc_multiple_port_num {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "ports": [{ "name": "http", "containerPort": "8080"}, { "name": "https", "containerPort": "8443"}], "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters_only_svc}
    inv := inv_svc({"app.kubernetes.io/name": "test"}, [{ "name": "name-of-service-port", "port": "80", "targetPort": "8080"}, { "name": "name-of-service-port", "port": "443", "targetPort": "8443"}])
    results := violation with input as input with data.inventory as inv
    count(results) == 1
}

test_one_ctr_no_violation_with_svc_port_name {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "ports": [{ "name": "http", "containerPort": "8080"}], "readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters_only_svc}
    inv := inv_svc({"app.kubernetes.io/name": "test"}, [{ "name": "name-of-service-port", "port": "80", "targetPort": "http"}])
    results := violation with input as input with data.inventory as inv
    count(results) == 0
}

test_one_ctr_no_violation_with_svc_port_num {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "ports": [{ "name": "http", "containerPort": "8080"}], "readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters_only_svc}
    inv := inv_svc({"app.kubernetes.io/name": "test"}, [{ "name": "name-of-service-port", "port": "80", "targetPort": "8080"}])
    results := violation with input as input with data.inventory as inv
    count(results) == 0
}

test_one_ctr_missing_both_no_violation_without_svc_port_num {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "ports": [{ "name": "http", "containerPort": "8080"}]}]),
              "parameters": parameters_only_svc}
    inv := inv_svc({"app.kubernetes.io/name": "non-matching-pod-selector"}, [{ "name": "name-of-service-port", "port": "80", "targetPort": "8080"}])
    results := violation with input as input with data.inventory as inv
    count(results) == 0
}

review(containers) = obj {
    obj = {
            "kind": {
                "kind": "Pod"
            },
            "object": {
                "metadata": {
                    "name": "some-name",
                    "namespace": namespace,
                    "labels": {
                        "app.kubernetes.io/name": "test"
                    }
                },
                "spec": {
                    "containers": containers
                }
            }
        }
}

svc_out(selector, ports) = output {
  output := {
    "apiVersion": "v1",
    "kind": "Service",
    "metadata": {
      "name": "example-service",
      "namespace": namespace,
    },
    "spec": {
      "selector": selector,
      "ports": ports,
    },
  }
}

inventory(obj) = output {
  output := {"namespace": {namespace: {obj.apiVersion: {obj.kind: [obj]}}}}
}

inv_svc(selector, ports) = output {
  svc = svc_out(selector, ports)
  output := inventory(svc)
}

namespace := "default"
parameters = {"probes": ["readinessProbe", "livenessProbe"], "probeTypes": ["tcpSocket", "httpGet", "exec"]}
parameters_only_svc = {"onlyServices": true, "probes": ["readinessProbe", "livenessProbe"], "probeTypes": ["tcpSocket", "httpGet", "exec"]}
kinds = ["Pod"]
