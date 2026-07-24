package k8srequiredlabels

test_input_no_required_labels {
    inp := { "review": review({"some": "label"}), "parameters": {}}
    results := violation with input as inp
    count(results) == 0
}
test_input_no_required_labels {
    inp := { "review": empty, "parameters": {}}
    results := violation with input as inp
    count(results) == 0
}
test_input_has_label {
    inp := { "review": review({"some": "label"}), "parameters": {"labels": [lbl("some", "label")]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_has_extra_label {
    inp := { "review": review({"some": "label", "new": "thing"}), "parameters": {"labels": [lbl("some", "label")]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_has_extra_label_req2 {
    inp := { "review": review({"some": "label", "new": "thing"}), "parameters": {"labels": [lbl("some", "label"), lbl("new", "thing")]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_missing_label {
    inp := { "review": review({"some_other": "label"}), "parameters": {"labels": [lbl("some", "label")]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_wrong_value {
    inp := { "review": review({"some": "label2"}), "parameters": {"labels": [lbl("some", "label$")]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_one_missing {
    inp := { "review": review({"some": "label"}), "parameters": {"labels": [lbl("some", "label"), lbl("other", "label")]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_wrong_empty {
    inp := { "review": empty, "parameters": {"labels": [lbl("some", "label$")]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_two_missing {
    inp := { "review": empty, "parameters": {"labels": [lbl("some", "label"), lbl("other", "label")]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_two_wrong {
    inp := { "review": review({"some": "lbe", "other": "lbe"}), "parameters": {"labels": [lbl("some", "label"), lbl("other", "label")]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_two_allowed {
    inp := { "review": review({"some": "gray", "other": "grey"}), "parameters": {"labels": [lbl("some", "gr[ae]y"), lbl("other", "gr[ae]y")]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_message {
    inp := { "review": review({"some": "label2"}), "parameters": {"message": "WRONG_VALUE", "labels": [lbl("some", "label$")]}}
    results := violation with input as inp
    results[_].msg == "WRONG_VALUE"
}

empty = {
  "object": {
    "metadata": {
      "name": "nginx"
    },
  }

}

review(labels) = output {
  output = {
    "object": {
      "metadata": {
        "name": "nginx",
        "labels": labels,
      },
    }
  }
}

lbl(k, v) = out {
  out = {"key": k, "allowedRegex": v}
}
