package k8sstorageclass

test_input_denied_no_datasync {
    input := { "review": input_review_pvc_name("fast"), "parameters": { "includeStorageClassesInMessage": true } }
    results := violation with input as input with data.inventory as inv_nosync
    results[result]
    contains(result.msg, "misconfigured")
}
test_input_allowed_pvc_fast {
    input := { "review": input_review_pvc_name("fast"), "parameters": { "includeStorageClassesInMessage": true } }
    results := violation with input as input with data.inventory as inv
    count(results) == 0
}
test_input_allowed_pvc_slow {
    input := { "review": input_review_pvc_name("slow"), "parameters": { "includeStorageClassesInMessage": true } }
    results := violation with input as input with data.inventory as inv
    count(results) == 0
}
test_input_denied_pvc_bad_storageclassname {
    input := { "review": input_review_pvc_name("other"), "parameters": { "includeStorageClassesInMessage": true } }
    results := violation with input as input with data.inventory as inv
    count(results) == 1
}
test_input_denied_pvc_bad_storageclassname_excludestorageclassesinmessage {
    input := { "review": input_review_pvc_name("other"), "parameters": { "includeStorageClassesInMessage": false } }
    results := violation with input as input with data.inventory as inv
    count(results) == 1
}
test_input_denied_pvc_storageclassname_missing {
    input := { "review": input_review_pvc_storageclassname_missing, "parameters": { "includeStorageClassesInMessage": true } }
    results := violation with input as input with data.inventory as inv
    count(results) == 1
}
test_input_allowed_statefulset_fast {
    input := { "review": input_review_statefulset_name("fast"), "parameters": { "includeStorageClassesInMessage": true } }
    results := violation with input as input with data.inventory as inv
    count(results) == 0
}
test_input_allowed_statefulset_slow {
    input := { "review": input_review_statefulset_name("slow"), "parameters": { "includeStorageClassesInMessage": true } }
    results := violation with input as input with data.inventory as inv
    count(results) == 0
}
test_input_denied_statefulset_bad_storageclassname {
    input := { "review": input_review_statefulset_name("other"), "parameters": { "includeStorageClassesInMessage": true } }
    results := violation with input as input with data.inventory as inv
    count(results) == 1
}
test_input_denied_statefulset_storageclassname_missing {
    input := { "review": input_review_statefulset_storageclassname_missing, "parameters": { "includeStorageClassesInMessage": true } }
    results := violation with input as input with data.inventory as inv
    count(results) == 1
}

input_review_pvc_name(name) = output {
  output = {
    "object": {
      "apiVersion": "v1",
      "kind": "PersistentVolumeClaim",
      "metadata": {
        "name": "foo"
      },
      "spec": {
        "accessModes": ["ReadWriteOnce"],
        "volumeMode": "Filesystem",
        "resources": {
          "requests": {
            "storage": "8Gi"
          }
        },
        "storageClassName": name
      }
    }
  }
}

input_review_pvc_storageclassname_missing = {
  "object": {
    "apiVersion": "v1",
    "kind": "PersistentVolumeClaim",
    "metadata": {
      "name": "foo"
    },
    "spec": {
      "accessModes": ["ReadWriteOnce"],
      "volumeMode": "Filesystem",
      "resources": {
        "requests": {
          "storage": "8Gi"
        }
      },
    }
  }
}

input_review_statefulset_name(name) = output {
  output = {
    "object": {
      "apiVersion": "apps/v1",
      "kind": "StatefulSet",
      "metadata": {
        "name": "foo"
      },
      "spec": {
        "volumeClaimTemplates": [{
          "metadata": {"name": "bar"},
          "spec": {
            "accessModes": ["ReadWriteOnce"],
            "volumeMode": "Filesystem",
            "resources": {
              "requests": {
                "storage": "8Gi"
              }
            },
            "storageClassName": name
          }
        }]
      }
    }
  }
}

input_review_statefulset_storageclassname_missing = {
  "object": {
    "apiVersion": "apps/v1",
    "kind": "StatefulSet",
    "metadata": {
      "name": "foo"
    },
    "spec": {
      "volumeClaimTemplates": [{
        "metadata": {"name": "bar"},
        "spec": {
          "accessModes": ["ReadWriteOnce"],
          "volumeMode": "Filesystem",
          "resources": {
            "requests": {
              "storage": "8Gi"
            }
          },
        }
      }]
    }
  }
}

inv = {
  "cluster": {
    "storage.k8s.io/v1": {
      "StorageClass": {
        "fast": {
          "somestuff": 1
        },
        "slow": {
          "somestuff": 2
        },
      }
    }
  }
}

inv_nosync = {
  "cluster": {
  }
}
