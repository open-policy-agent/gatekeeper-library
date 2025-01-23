package noupdateserviceaccount

import rego.v1

privileged(user_info, allowed_users, _) if {
	# Allow if the user is in allowedUsers.
	# Use object.get so omitted parameters can't cause policy bypass by
	# evaluating to undefined.
	username := object.get(user_info, "username", "")
	username in allowed_users
}

privileged(user_info, _, allowed_groups) if {
	# Allow if the user's groups intersect allowedGroups.
	# Use object.get so omitted parameters can't cause policy bypass by
	# evaluating to undefined.
	groups := {g | some g in user_info.groups}
	allowed := {g | some g in allowed_groups}
	common := groups & allowed
	count(common) > 0
}

get_service_account(obj) := obj.spec.serviceAccountName if obj.kind == "Pod"

get_service_account(obj) := obj.spec.template.spec.serviceAccountName if obj.kind == "ReplicationController"

get_service_account(obj) := obj.spec.template.spec.serviceAccountName if obj.kind == "ReplicaSet"

get_service_account(obj) := obj.spec.template.spec.serviceAccountName if obj.kind == "Deployment"

get_service_account(obj) := obj.spec.template.spec.serviceAccountName if obj.kind == "StatefulSet"

get_service_account(obj) := obj.spec.template.spec.serviceAccountName if obj.kind == "DaemonSet"

get_service_account(obj) := obj.spec.template.spec.serviceAccountName if obj.kind == "Job"

get_service_account(obj) := obj.spec.jobTemplate.spec.template.spec.serviceAccountName if obj.kind == "CronJob"

violation contains {"msg": msg} if {
	# This policy only applies to updates of existing resources.
	input.review.operation == "UPDATE"

	# Use object.get so omitted parameters can't cause policy bypass by
	# evaluating to undefined.
	params := object.get(input, "parameters", {})
	allowed_users := object.get(params, "allowedUsers", [])
	allowed_groups := object.get(params, "allowedGroups", [])

	# Deny unprivileged users and groups from changing serviceAccountName.
	not privileged(input.review.userInfo, allowed_users, allowed_groups)

	# Extract the service account.
	old_ksa := get_service_account(input.review.oldObject)
	new_ksa := get_service_account(input.review.object)
	old_ksa != new_ksa

	msg := "user does not have permission to modify serviceAccountName"
}

violation contains {"msg": msg} if {
	# Defensively require object to have a serviceAccountName.
	input.review.operation == "UPDATE"
	not get_service_account(input.review.object)
	msg := "missing serviceAccountName field in object under review"
}

violation contains {"msg": msg} if {
	# Defensively require oldObject to have a serviceAccountName.
	input.review.operation == "UPDATE"
	not get_service_account(input.review.oldObject)
	msg := "missing serviceAccountName field in oldObject under review"
}
