package k8sdisallowanonymous

import rego.v1

violation contains {"msg": message(group)} if {
	not input.review.object.roleRef.name in allowed_roles
	some group in ["system:unauthenticated", "system:anonymous"]
	some subject in input.review.object.subjects
	subject.name == group
}

violation contains {"msg": message("system:authenticated")} if {
	not input.review.object.roleRef.name in allowed_roles
	input.parameters.disallowAuthenticated
	some subject in input.review.object.subjects
	subject.name == "system:authenticated"
}

default allowed_roles := []

allowed_roles := input.parameters.allowedRoles

message(name) := sprintf("%v is not allowed as a subject name in %v %v", [
	name,
	input.review.object.kind,
	input.review.object.metadata.name,
])
