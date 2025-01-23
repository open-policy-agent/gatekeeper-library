package k8sblocknodeport

import rego.v1

test_block_node_port if {
	inp := {"review": {
		"kind": {"kind": "Service"},
		"object": {
			"spec": {"type": "NodePort"},
			"ports": {
				"port": 80,
				"targetPort": 80,
				"nodePort": 30007,
			},
		},
	}}
	result := violation with input as inp
	count(result) == 1
}

test_allow_other_service_types if {
	inp := {"review": {
		"kind": {"kind": "Service"},
		"object": {
			"spec": {"type": "LoadBalancer"},
			"ports": {
				"protocol": "TCP",
				"port": 80,
				"targetPort": 9376,
			},
		},
	}}
	result := violation with input as inp
	count(result) == 0
}
