package k8snodeportnamespacerange

test_allow_nodeport_in_range {
  not violation with input as {
    "review": {
      "object": {
        "metadata": {
          "namespace": "dev-team"
        },
        "spec": {
          "type": "NodePort",
          "ports": [
            { "nodePort": 30010 }
          ]
        }
      }
    },
    "parameters": {
      "ranges": {
        "dev": {
          "namespacePattern": "dev-*",
          "portRange": "[30000:30020]"
        }
      }
    }
  }
}

test_deny_nodeport_out_of_range {
  violation[_] with input as {
    "review": {
      "object": {
        "metadata": {
          "namespace": "dev-team"
        },
        "spec": {
          "type": "NodePort",
          "ports": [
            { "nodePort": 31000 }
          ]
        }
      }
    },
    "parameters": {
      "ranges": {
        "dev": {
          "namespacePattern": "dev-*",
          "portRange": "[30000:30020]"
        }
      }
    }
  }
}
