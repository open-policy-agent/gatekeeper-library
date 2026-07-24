package verifydeprecatedapi

test_hpa_with_deprecated_api {
    inp := {"review": hpa("autoscaling/v2beta2"), "parameters": {"kvs": [{"deprecatedAPI": "autoscaling/v2beta2", "kinds": ["HorizontalPodAutoscaler"], "targetAPI": "autoscaling/v2"}], "k8sVersion": 1.26}}
    results := violation with input as inp
    count(results) == 0
}

test_hpa_without_deprecated_api {
    inp := {"review": hpa("autoscaling/v2"), "parameters": {"kvs": [{"deprecatedAPI": "autoscaling/v2beta2", "kinds": ["HorizontalPodAutoscaler"], "targetAPI": "autoscaling/v2"}], "k8sVersion": 1.26}}
    results := violation with input as inp
    count(results) == 0
}

hpa(api) = output {
  output :=  {
    "apiVersion": api,
    "kind": "HorizontalPodAutoscaler",
    "metadata": {
      "name": "nginx-deployment",
      "namespace": "default"
    },
    "spec": {
      "maxReplicas": "10",
      "metrics": [{
        "resource": {
          "name": "cpu",
          "target": {
            "averageUtilization": "80",
            "type": "Utilization"
          }
        },
        "type": "Resource"
      }],
      "minReplicas": "1",
      "scaleTargetRef": {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "name": "nginx-deployment"
      }
    }
  }
}
