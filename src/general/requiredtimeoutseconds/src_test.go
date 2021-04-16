package k8srequiredtimeoutseconds

test_one_ctr_no_violations {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest","readinessProbe": {"tcpSocket": {"port":80}, "timeoutSeconds" : 10}, "livenessProbe": {"tcpSocket": {"port":80}, "timeoutSeconds" : 10}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 0
}

test_one_ctr_no_probes_no_violation {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest"}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 0
}

test_one_ctr_liveness_violation {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_one_ctr_readiness_violation {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_one_ctr_all_violations_in_both {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container","image": "my-image:latest","readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {"tcpSocket": {"port":80}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
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
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}, "timeoutSeconds" : 10}},
                                {"name": "my-container2","image": "my-image:latest","readinessProbe": {"tcpSocket": {"port":8080}}, "livenessProbe": {"tcpSocket": {"port":8080}, "timeoutSeconds" : 10}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 1
}

test_two_ctrs_liveness_violation_in_both_ctr {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "livenessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest","readinessProbe": {"tcpSocket": {"port":8080}, "timeoutSeconds" : 10}, "livenessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_readiness_violation_in_both_ctr {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}},
                                {"name": "my-container2","image": "my-image:latest","livenessProbe": {"tcpSocket": {"port":8080}, "timeoutSeconds" : 10}, "readinessProbe": {"tcpSocket": {"port":8080}}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 2
}

test_two_ctrs_no_probes_no_violations {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest"},
                                {"name": "my-container2","image": "my-image:latest"}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 0
}

test_two_ctrs_empty_liveness_in_ctr_two_both_empty_probes_in_ctr_one {
    kind := kinds[_]
    input := {"review": review([{"name": "my-container1","image": "my-image:latest", "readinessProbe": {}, "livenessProbe": {}},
                                {"name": "my-container2","image": "my-image:latest", "readinessProbe": {"tcpSocket": {"port":80}}, "livenessProbe": {}}]),
              "parameters": parameters}
    results := violation with input as input
    count(results) == 4
}



review(containers) = obj {
    obj = {
            "kind": {
                "kind": "Pod"
            },
            "object": {
                "metadata": {
                    "name": "some-name"
                },
                "spec": {
                    "containers":containers
                }
            }
        }
}

parameters = {"probes": ["readinessProbe", "livenessProbe"]}
kinds = ["Pod"]
