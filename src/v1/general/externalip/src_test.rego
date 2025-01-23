package k8sexternalips

import rego.v1

test_input_non_svc if {
	inp := {"review": non_svc, "parameters": {"allowedIPs": ["1.2.3.4"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_no_external_ip if {
	inp := {"review": non_externalip_svc, "parameters": {"allowedIPs": ["1.2.3.4"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_no_violations_externalip if {
	inp := {"review": externalip_svc(["1.2.3.4"]), "parameters": {"allowedIPs": ["1.2.3.4"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_no_violations_externalip_multiple if {
	inp := {"review": externalip_svc(["1.2.3.4", "203.0.113.0"]), "parameters": {"allowedIPs": ["1.1.1.1", "203.0.113.0", "1.2.3.4", "203.0.113.1"]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_no_violations_empty if {
	inp := {"review": externalip_svc([]), "parameters": {"allowedIPs": []}}
	results := violation with input as inp
	count(results) == 0
}

test_input_violations_externalip if {
	inp := {"review": externalip_svc(["203.0.113.0"]), "parameters": {"allowedIPs": ["1.1.1.1", "1.2.3.4"]}}
	results := violation with input as inp
	results
	count(results) == 1
}

test_input_violations_none_allowed if {
	inp := {"review": externalip_svc(["203.0.113.0"]), "parameters": {"allowedIPs": []}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_partial if {
	inp := {"review": externalip_svc(["1.2.3.4", "203.0.113.0"]), "parameters": {"allowedIPs": ["1.1.1.1", "1.2.3.4", "203.0.113.1"]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_violations_multiple if {
	inp := {"review": externalip_svc(["1.2.3.4", "203.0.113.0"]), "parameters": {"allowedIPs": ["1.1.1.1", "203.0.113.1"]}}
	results := violation with input as inp
	count(results) == 1 # Multiple failing IPs reported in single error message.
}

externalip_svc(ips) := {
	"kind": {
		"group": "",
		"version": "v1",
		"kind": "Service",
	},
	"object": {
		"metadata": {"name": "baz"},
		"spec": {"externalIPs": ips},
	},
}

non_externalip_svc := {
	"kind": {
		"group": "",
		"version": "v1",
		"kind": "Service",
	},
	"object": {
		"metadata": {"name": "baz"},
		"spec": {
			"selector": "MyApp",
			"ports": [{
				"name": "http",
				"protocol": "TCP",
				"port": 80,
				"targetPort": 8080,
			}],
		},
	},
}

non_svc := {
	"kind": {
		"group": "",
		"version": "v1",
		"kind": "Foo",
	},
	"object": {
		"metadata": {"name": "bar"},
		"spec": {"externalIPs": ["1.1.1.1"]},
	},
}
