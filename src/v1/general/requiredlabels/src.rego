package k8srequiredlabels

import rego.v1

violation contains {"msg": msg, "details": {"missing_labels": missing}} if {
	provided := {label | some label in object.keys(input.review.object.metadata.labels)}
	required := {label.key | some label in input.parameters.labels}
	missing := required - provided
	count(missing) > 0
	def_msg := sprintf("you must provide labels: %v", [missing])
	msg := get_message(input.parameters, def_msg)
}

violation contains {"msg": msg} if {
	some key, value in input.review.object.metadata.labels
	some expected in input.parameters.labels
	expected.key == key

	# do not match if allowedRegex is not defined, or is an empty string
	expected.allowedRegex != ""
	not regex.match(expected.allowedRegex, value)
	def_msg := sprintf("Label <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
	msg := get_message(input.parameters, def_msg)
}

get_message(parameters, _default) := _default if {
	not parameters.message
}

get_message(parameters, _) := parameters.message
