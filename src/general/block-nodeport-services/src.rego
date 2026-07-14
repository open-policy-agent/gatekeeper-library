package k8sblocknodeport

import future.keywords.contains
import future.keywords.if

violation contains ({"msg": msg}) if {
  input.review.kind.kind == "Service"
  input.review.object.spec.type == "NodePort"
  msg := "User is not allowed to create service of type NodePort"
}
