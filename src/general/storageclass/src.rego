package k8sstorageclass

import future.keywords.contains
import future.keywords.if

is_pvc(obj) if {
  obj.apiVersion == "v1"
  obj.kind == "PersistentVolumeClaim"
}

is_statefulset(obj) if {
  obj.apiVersion == "apps/v1"
  obj.kind == "StatefulSet"
}

violation contains ({"msg": msg}) if {
  not data.inventory.cluster["storage.k8s.io/v1"].StorageClass
  msg := sprintf("StorageClasses not synced. Gatekeeper may be misconfigured. Please have a cluster-admin consult the documentation.", [])
}

storageclass_allowed(name) if {
  data.inventory.cluster["storage.k8s.io/v1"].StorageClass[name]

  # support both direct use of * and as the default value
  object.get(input.parameters, "allowedStorageClasses", ["*"])[_] == "*"
}

storageclass_allowed(name) if {
  data.inventory.cluster["storage.k8s.io/v1"].StorageClass[name]
  input.parameters.allowedStorageClasses[_] == name
}

violation contains {"msg": pvc_storageclass_badname_msg} if {
  is_pvc(input.review.object)
  not storageclass_allowed(input.review.object.spec.storageClassName)
}

pvc_storageclass_badname_msg := sprintf("pvc did not specify a valid storage class name <%v>. Must be one of [%v]", args) if {
  input.parameters.includeStorageClassesInMessage
  object.get(input.parameters, "allowedStorageClasses", null) == null
  args := [
    input.review.object.spec.storageClassName,
    concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][n]])
  ]
} else := sprintf("pvc did not specify an allowed and valid storage class name <%v>. Must be one of [%v]", args) if {
  input.parameters.includeStorageClassesInMessage
  object.get(input.parameters, "allowedStorageClasses", null) != null
  sc := {n | data.inventory.cluster["storage.k8s.io/v1"].StorageClass[n]} & {x | x = object.get(input.parameters, "allowedStorageClasses", [])[_]}
  args := [
    input.review.object.spec.storageClassName,
    concat(", ", sc)
  ]
} else := sprintf(
  "pvc did not specify a valid storage class name <%v>.",
  [input.review.object.spec.storageClassName],
)

violation contains {"msg": pvc_storageclass_noname_msg} if {
  is_pvc(input.review.object)
  not input.review.object.spec.storageClassName
}

pvc_storageclass_noname_msg := sprintf("pvc did not specify a storage class name. Must be one of [%v]", args) if {
  input.parameters.includeStorageClassesInMessage
  args := [
    concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][n]])
  ]
} else := sprintf(
  "pvc did not specify a storage class name.",
  [],
)

violation contains {"msg": statefulset_vct_badname_msg(vct)} if {
  is_statefulset(input.review.object)
  vct := input.review.object.spec.volumeClaimTemplates[_]
  not storageclass_allowed(vct.spec.storageClassName)
}

statefulset_vct_badname_msg(vct) := msg if {
  input.parameters.includeStorageClassesInMessage
  object.get(input.parameters, "allowedStorageClasses", null) == null
  msg := sprintf(
      "statefulset did not specify a valid storage class name <%v>. Must be one of [%v]", [
      vct.spec.storageClassName,
      concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][n]])
  ])
}

statefulset_vct_badname_msg(vct) := msg if {
  input.parameters.includeStorageClassesInMessage
  object.get(input.parameters, "allowedStorageClasses", null) != null
  sc := {n | data.inventory.cluster["storage.k8s.io/v1"].StorageClass[n]} & {x | x = object.get(input.parameters, "allowedStorageClasses", [])[_]}
  msg := sprintf(
      "statefulset did not specify an allowed and valid storage class name <%v>. Must be one of [%v]", [
      vct.spec.storageClassName,
      concat(", ", sc)
  ])
}

statefulset_vct_badname_msg(vct) := msg if {
  not input.parameters.includeStorageClassesInMessage
  msg := sprintf(
    "statefulset did not specify a valid storage class name <%v>.", [
      vct.spec.storageClassName
  ])
}

violation contains {"msg": statefulset_vct_noname_msg} if {
  is_statefulset(input.review.object)
  vct := input.review.object.spec.volumeClaimTemplates[_]
  not vct.spec.storageClassName
}

statefulset_vct_noname_msg := sprintf("statefulset did not specify a storage class name. Must be one of [%v]", args) if {
  input.parameters.includeStorageClassesInMessage
  args := [
    concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][n]])
  ]
} else := sprintf(
  "statefulset did not specify a storage class name.",
  [],
)
