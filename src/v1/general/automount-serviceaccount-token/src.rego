package k8sautomountserviceaccounttoken

import rego.v1

import data.lib.exclude_update.is_update

violation contains {"msg": msg} if {
	# spec.automountServiceAccountToken and spec.containers.volumeMounts fields are immutable.
	not is_update(input.review)
	mount_service_account_token(input.review.object.spec)

	msg := sprintf("Automounting service account token is disallowed, pod: %v", [input.review.object.metadata.name])
}

mount_service_account_token(spec) if spec.automountServiceAccountToken == true

# if there is no automountServiceAccountToken spec, check on volumeMount in containers. Service Account token is
# mounted on /var/run/secrets/kubernetes.io/serviceaccount
# https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#serviceaccount-admission-controller
mount_service_account_token(spec) if {
	not "automountServiceAccountToken" in object.keys(spec)

	# Ephemeral containers not checked as it is not possible to set field.
	some type in ["containers", "initContainers"]
	some container in input.review.object.spec[type]

	"/var/run/secrets/kubernetes.io/serviceaccount" == container.volumeMounts[_].mountPath
}
