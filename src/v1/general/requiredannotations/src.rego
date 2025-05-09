package k8srequiredannotations

import rego.v1

violation contains {"msg": msg, "details": {"missing_annotations": missing}} if {
	provided := {key | some key in object.keys(input.review.object.metadata.annotations)}
	required := {annotation.key | some annotation in input.parameters.annotations}
	missing := required - provided
	count(missing) > 0
	msg := sprintf("you must provide annotation(s): %v", [missing])
}

violation contains {"msg": msg} if {
	some key, value in input.review.object.metadata.annotations
	some expected in input.parameters.annotations
	expected.key == key
	expected.allowedRegex != ""
	not regex.match(expected.allowedRegex, value)
	msg := sprintf("Annotation <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
}
