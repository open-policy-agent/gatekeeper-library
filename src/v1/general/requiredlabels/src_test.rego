package k8srequiredlabels

import rego.v1

test_input_no_required_labels_some_provided if {
	inp := {"review": review({"some": "label"}), "parameters": {}}
	results := violation with input as inp
	count(results) == 0
}

test_input_no_required_labels_none_provided if {
	inp := {"review": empty, "parameters": {}}
	results := violation with input as inp
	count(results) == 0
}

test_input_has_label if {
	inp := {"review": review({"some": "label"}), "parameters": {"labels": [lbl("some", "label")]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_has_extra_label if {
	inp := {"review": review({"some": "label", "new": "thing"}), "parameters": {"labels": [lbl("some", "label")]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_has_extra_label_req2 if {
	inp := {"review": review({"some": "label", "new": "thing"}), "parameters": {"labels": [lbl("some", "label"), lbl("new", "thing")]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_missing_label if {
	inp := {"review": review({"some_other": "label"}), "parameters": {"labels": [lbl("some", "label")]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_wrong_value if {
	inp := {"review": review({"some": "label2"}), "parameters": {"labels": [lbl("some", "label$")]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_one_missing if {
	inp := {"review": review({"some": "label"}), "parameters": {"labels": [lbl("some", "label"), lbl("other", "label")]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_wrong_empty if {
	inp := {"review": empty, "parameters": {"labels": [lbl("some", "label$")]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_two_missing if {
	inp := {"review": empty, "parameters": {"labels": [lbl("some", "label"), lbl("other", "label")]}}
	results := violation with input as inp
	count(results) == 1
}

test_input_two_wrong if {
	inp := {"review": review({"some": "lbe", "other": "lbe"}), "parameters": {"labels": [lbl("some", "label"), lbl("other", "label")]}}
	results := violation with input as inp
	count(results) == 2
}

test_input_two_allowed if {
	inp := {"review": review({"some": "gray", "other": "grey"}), "parameters": {"labels": [lbl("some", "gr[ae]y"), lbl("other", "gr[ae]y")]}}
	results := violation with input as inp
	count(results) == 0
}

test_input_message if {
	inp := {"review": review({"some": "label2"}), "parameters": {"message": "WRONG_VALUE", "labels": [lbl("some", "label$")]}}
	results := violation with input as inp
	results[_].msg == "WRONG_VALUE"
}

empty := {"object": {"metadata": {"name": "nginx"}}}

review(labels) := {"object": {"metadata": {
	"name": "nginx",
	"labels": labels,
}}}

lbl(k, v) := {"key": k, "allowedRegex": v}
