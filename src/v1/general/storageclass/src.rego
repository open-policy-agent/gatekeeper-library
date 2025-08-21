package k8sstorageclass

import rego.v1

violation contains {"msg": msg} if {
	not data.inventory.cluster["storage.k8s.io/v1"].StorageClass

	# regal ignore:line-length
	msg := "StorageClasses not synced. Gatekeeper may be misconfigured. Please have a cluster-admin consult the documentation."
}

violation contains {"msg": pvc_storageclass_badname_msg} if {
	is_pvc(input.review.object)
	not storageclass_allowed(input.review.object.spec.storageClassName)
}

violation contains {"msg": pvc_storageclass_noname_msg} if {
	is_pvc(input.review.object)
	not input.review.object.spec.storageClassName
}

violation contains {"msg": statefulset_vct_badname_msg(vct)} if {
	is_statefulset(input.review.object)
	some vct in input.review.object.spec.volumeClaimTemplates
	not storageclass_allowed(vct.spec.storageClassName)
}

violation contains {"msg": statefulset_vct_noname_msg} if {
	is_statefulset(input.review.object)
	some vct in input.review.object.spec.volumeClaimTemplates
	not vct.spec.storageClassName
}

is_pvc(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "PersistentVolumeClaim"
}

is_statefulset(obj) if {
	obj.apiVersion == "apps/v1"
	obj.kind == "StatefulSet"
}

storageclass_allowed(name) if {
	data.inventory.cluster["storage.k8s.io/v1"].StorageClass[name]

	# support both direct use of * and as the default value
	"*" in object.get(input.parameters, "allowedStorageClasses", ["*"])
}

storageclass_allowed(name) if {
	data.inventory.cluster["storage.k8s.io/v1"].StorageClass[name]
	name in input.parameters.allowedStorageClasses
}

pvc_storageclass_badname_msg := msg if {
	input.parameters.includeStorageClassesInMessage
	object.get(input.parameters, "allowedStorageClasses", null) == null
	args := [
		input.review.object.spec.storageClassName,
		concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"].StorageClass[n]]),
	]
	msg := sprintf("pvc did not specify a valid storage class name <%v>. Must be one of [%v]", args)
} else := msg if {
	input.parameters.includeStorageClassesInMessage
	object.get(input.parameters, "allowedStorageClasses", null) != null

	isc := object.keys(data.inventory.cluster["storage.k8s.io/v1"].StorageClass)
	asc := object.get(input.parameters, "allowedStorageClasses", [])

	some sc in (isc & asc)
	args := [
		input.review.object.spec.storageClassName,
		concat(", ", sc),
	]
	msg := sprintf("pvc did not specify an allowed and valid storage class name <%v>. Must be one of [%v]", args)
} else := sprintf(
	"pvc did not specify a valid storage class name <%v>.",
	[input.review.object.spec.storageClassName],
)

pvc_storageclass_noname_msg := sprintf("pvc did not specify a storage class name. Must be one of [%v]", args) if {
	input.parameters.includeStorageClassesInMessage
	args := [concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"].StorageClass[n]])]
} else := sprintf(
	"pvc did not specify a storage class name.",
	[],
)

statefulset_vct_badname_msg(vct) := msg if {
	input.parameters.includeStorageClassesInMessage
	object.get(input.parameters, "allowedStorageClasses", null) == null
	msg := sprintf("statefulset did not specify a valid storage class name <%v>. Must be one of [%v]", [
		vct.spec.storageClassName,
		concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"].StorageClass[n]]),
	])
}

statefulset_vct_badname_msg(vct) := msg if {
	input.parameters.includeStorageClassesInMessage
	object.get(input.parameters, "allowedStorageClasses", null) != null

	isc := {n | some n in object.keys(data.inventory.cluster["storage.k8s.io/v1"].StorageClass)}
	asc := {n | some n in object.get(input.parameters, "allowedStorageClasses", [])}
	sc := isc & asc

	msg := sprintf("statefulset did not specify an allowed and valid storage class name <%v>. Must be one of [%v]", [
		vct.spec.storageClassName,
		concat(", ", sc),
	])
}

statefulset_vct_badname_msg(vct) := msg if {
	not input.parameters.includeStorageClassesInMessage
	msg := sprintf("statefulset did not specify a valid storage class name <%v>.", [vct.spec.storageClassName])
}

default statefulset_vct_noname_msg := "statefulset did not specify a storage class name."

statefulset_vct_noname_msg := msg if {
	input.parameters.includeStorageClassesInMessage
	msg := sprintf(
		"statefulset did not specify a storage class name. Must be one of [%v]",
		[concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"].StorageClass[n]])],
	)
}
