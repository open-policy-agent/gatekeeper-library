package k8sknativereplica

test_replicas_no_violation {
    input := { "review": review(2, 9, 1) , "parameters": {"replicas": "10"}}
    results := violation with input as input
    count(results) == 0
}

test_replicas_no_annotations {
    input := { "review": review_annotations , "parameters": {"replicas": "10"}}
    results := violation with input as input
    count(results) == 0
}

test_replicas_empty_maxScale {
    input := { "review": review(2, "", 1) , "parameters": {"replicas": "10"}}
    results := violation with input as input
    count(results) == 0
}

test_replicas_maxScale_greater_than_replicas{
    input := { "review": review(2, 11, 1) , "parameters": {"replicas": "10"}}
    results := violation with input as input
    count(results) == 1
}

test_replicas_minScale_greater_than_maxScale {
    input := { "review": review(8, 7, 1) , "parameters": {"replicas": "10"}}
    results := violation with input as input
    count(results) == 1
}

test_replicas_minScale_greater_than_replicas {
    input := { "review": review_minScale(12) , "parameters": {"replicas": "10"}}
    results := violation with input as input
    count(results) == 1
}

test_replicas_initialScale_greater_than_replicas {
    input := { "review": review(2, 8, 11) , "parameters": {"replicas": "10"}}
    results := violation with input as input
    count(results) == 1
}

review(minScale, maxScale, initialScale) = output {
  output = {
    "object": {
      "spec": {
        "template": {
            "metadata": {
               "annotations": {
                 "autoscaling.knative.dev/minScale": minScale,
                 "autoscaling.knative.dev/maxScale": maxScale,
                 "autoscaling.knative.dev/initialScale": initialScale,
               }
            }
        }
      }
    }
  }
} 

review_minScale(minScale) = output {
  output = {
    "object": {
      "spec": {
        "template": {
            "metadata": {
               "annotations": {
                 "autoscaling.knative.dev/minScale": minScale
               }
            }
        }
      }
    }
  }
} 

review_annotations = output {
  output = {
    "object": {
      "spec": {
        "template": {
            "metadata": {
                
            }
        }
      }
    }
  }
} 