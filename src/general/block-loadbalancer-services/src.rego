package k8sblockloadbalancer

violation[{"msg": msg}] {
  input.review.kind.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  msg := "User is not allowed to create service of type LoadBalancer"
}
