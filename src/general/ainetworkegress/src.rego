package k8sainetworkegress

# Block hostNetwork on AI workload pods when configured.
# hostNetwork=true bypasses all NetworkPolicy egress controls.
violation[{"msg": msg}] {
  input.parameters.blockHostNetwork == true
  input.review.object.spec.hostNetwork == true
  msg := "AI workload pod must not use spec.hostNetwork=true; it bypasses NetworkPolicy egress controls"
}

# Require pods to carry labels that declare their NetworkPolicy binding.
# This ensures a matching NetworkPolicy selector exists before the pod is admitted.
violation[{"msg": msg, "details": {"missing_labels": missing}}] {
  provided := {k | input.review.object.metadata.labels[k]}
  required := {lbl.key | lbl := input.parameters.requiredEgressLabels[_]}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("AI workload pod is missing required network egress label(s): %v", [missing])
}

violation[{"msg": msg}] {
  lbl := input.parameters.requiredEgressLabels[_]
  lbl.value != ""
  value := input.review.object.metadata.labels[lbl.key]
  lbl.value != value
  msg := sprintf("Network egress label <%v> must have value <%v>, got <%v>", [lbl.key, lbl.value, value])
}
