package k8sknativereplica

test_replicas_no_violation {
    input := { "review": review(2, 9, 1) , "parameters": {"replicas": "10"}}
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
    input := { "review": {"object": { "spec": { "template": { "metadata": { "annotations": {"autoscaling.knative.dev/minScale": 12}}}}}} , "parameters": {"replicas": "10"}}
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

