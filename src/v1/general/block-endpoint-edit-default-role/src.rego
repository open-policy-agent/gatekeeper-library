package k8sblockendpointeditdefaultrole

import rego.v1

violation contains {"msg": msg} if {
	input.review.object.metadata.name == "system:aggregate-to-edit"
	some rule in input.review.object.rules
	endpoint_rule(rule)

	# regal ignore:line-length
	msg := "ClusterRole system:aggregate-to-edit should not allow endpoint edit permissions. For k8s version < 1.22, the Cluster Role should be annotated with rbac.authorization.kubernetes.io/autoupdate=false to prevent autoreconciliation back to default permissions for this role."
}

endpoint_rule(rule) if {
	"endpoints" in rule.resources
	has_edit_verb(rule.verbs)
}

has_edit_verb(verbs) if "create" in verbs

has_edit_verb(verbs) if "patch" in verbs

has_edit_verb(verbs) if "update" in verbs
