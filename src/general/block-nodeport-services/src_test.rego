package k8sblocknodeport

test_block_node_port {
  inp := {
    "review": {
      "kind": {"kind": "Service"},
      "object": {
        "spec": {
          "type": "NodePort"
        },
        "ports": {
                "port": 80,
                "targetPort": 80,
                "nodePort": 30007
            }
        }
      }
  }
  result := violation with input as inp
  count(result) == 1
}
test_allow_other_service_types {
  inp := {
    "review": {
      "kind": {"kind": "Service"},
      "object": {
        "spec": {
          "type": "LoadBalancer"
        },
        "ports": {
                "protocol": "TCP",
                "port": 80,
                "targetPort": 9376,
            }
        }
      }
  }
  result := violation with input as inp
  count(result) == 0
}
