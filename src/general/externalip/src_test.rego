package k8sexternalips

test_input_non_svc {
    inp := {"review": non_svc, "parameters": {"allowedIPs": ["1.2.3.4"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_no_external_ip {
    inp := {"review": non_externalip_svc, "parameters": {"allowedIPs": ["1.2.3.4"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_no_violations_externalip {
    inp := {"review": externalip_svc(["1.2.3.4"]), "parameters": {"allowedIPs": ["1.2.3.4"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_no_violations_externalip_multiple {
    inp := {"review": externalip_svc(["1.2.3.4", "203.0.113.0"]), "parameters": {"allowedIPs": ["1.1.1.1", "203.0.113.0", "1.2.3.4", "203.0.113.1"]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_no_violations_empty {
    inp := {"review": externalip_svc([]), "parameters": {"allowedIPs": []}}
    results := violation with input as inp
    count(results) == 0
}
test_input_violations_externalip {
    inp := {"review": externalip_svc(["203.0.113.0"]), "parameters": {"allowedIPs": ["1.1.1.1", "1.2.3.4"]}}
    results := violation with input as inp
    results
    count(results) == 1
}
test_input_violations_none_allowed {
    inp := {"review": externalip_svc(["203.0.113.0"]), "parameters": {"allowedIPs": []}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_partial {
    inp := {"review": externalip_svc(["1.2.3.4", "203.0.113.0"]), "parameters": {"allowedIPs": ["1.1.1.1", "1.2.3.4", "203.0.113.1"]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_violations_multiple {
    inp := {"review": externalip_svc(["1.2.3.4", "203.0.113.0"]), "parameters": {"allowedIPs": ["1.1.1.1", "203.0.113.1"]}}
    results := violation with input as inp
    count(results) == 1 # Multiple failing IPs reported in single error message.
}

externalip_svc(ips) = output {
  output = {
    "kind": {
        "group": "",
        "version": "v1",
        "kind": "Service",
    },
    "object": {
      "metadata": {
        "name": "baz",
      },
      "spec": {
          "externalIPs": ips,
      }
    }
  }
}

non_externalip_svc = output {
  output = {
    "kind": {
        "group": "",
        "version": "v1",
        "kind": "Service",
    },
    "object": {
      "metadata": {
        "name": "baz",
      },
      "spec": {
          "selector": "MyApp",
          "ports": [{
              "name": "http",
              "protocol": "TCP",
              "port": 80,
              "targetPort": 8080,
          }]
      }
    }
  }
}

non_svc = output {
  output = {
    "kind": {
        "group": "",
        "version": "v1",
        "kind": "Foo",
    },
    "object": {
      "metadata": {
        "name": "bar",
      },
      "spec": {
          "externalIPs": ["1.1.1.1"],
      }
    }
  }
}
