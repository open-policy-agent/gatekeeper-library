package k8srequiredannotations

test_input_no_required_annotations {
    inp := { "review": review({"some": "annotation"}), "parameters": {}}
    results := violation with input as inp
    count(results) == 0
}
test_input_no_required_annotations {
    inp := { "review": empty, "parameters": {}}
    results := violation with input as inp
    count(results) == 0
}
test_input_has_annotation {
    inp := { "review": review({"some": "annotation"}), "parameters": {"annotations": [lbl("some", "annotation")]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_has_extra_annotation {
    inp := { "review": review({"some": "annotation", "new": "thing"}), "parameters": {"annotations": [lbl("some", "annotation")]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_has_extra_annotation_req2 {
    inp := { "review": review({"some": "annotation", "new": "thing"}), "parameters": {"annotations": [lbl("some", "annotation"), lbl("new", "thing")]}}
    results := violation with input as inp
    count(results) == 0
}
test_input_missing_annotation {
    inp := { "review": review({"some_other": "annotation"}), "parameters": {"annotations": [lbl("some", "annotation")]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_wrong_value {
    inp := { "review": review({"some": "annotation2"}), "parameters": {"annotations": [lbl("some", "annotation$")]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_one_missing {
    inp := { "review": review({"some": "annotation"}), "parameters": {"annotations": [lbl("some", "annotation"), lbl("other", "annotation")]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_wrong_empty {
    inp := { "review": empty, "parameters": {"annotations": [lbl("some", "label$")]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_two_missing {
    inp := { "review": empty, "parameters": {"annotations": [lbl("some", "annotation"), lbl("other", "annotation")]}}
    results := violation with input as inp
    count(results) == 1
}
test_input_two_wrong {
    inp := { "review": review({"some": "lbe", "other": "lbe"}), "parameters": {"annotations": [lbl("some", "annotation"), lbl("other", "annotation")]}}
    results := violation with input as inp
    count(results) == 2
}
test_input_two_allowed {
    inp := { "review": review({"some": "gray", "other": "grey"}), "parameters": {"annotations": [lbl("some", "gr[ae]y"), lbl("other", "gr[ae]y")]}}
    results := violation with input as inp
    count(results) == 0
}


empty = {
  "object": {
    "metadata": {
      "name": "service"
    },
  }

}

review(annotations) = output {
  output = {
    "object": {
      "metadata": {
        "name": "service",
        "annotations": annotations,
      },
    }
  }
}

lbl(k, v) = out {
  out = {"key": k, "allowedRegex": v}
}
