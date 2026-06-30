package k8sairequiredcontrols

# Verify required annotations are present with the expected values.
violation[{"msg": msg, "details": {"missing_annotations": missing}}] {
  provided := {k | input.review.object.metadata.annotations[k]}
  required := {req.key | req := input.parameters.requiredAnnotations[_]}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("AI workload is missing required annotation(s): %v", [missing])
}

violation[{"msg": msg}] {
  ann := input.parameters.requiredAnnotations[_]
  ann.value != ""
  value := input.review.object.metadata.annotations[ann.key]
  ann.value != value
  msg := sprintf("Annotation <%v> must have value <%v>, got <%v>", [ann.key, ann.value, value])
}

# Verify credential env vars use secretKeyRef and not a plain-text value.
violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  env := container.env[_]
  pattern := input.parameters.credentialEnvPatterns[_]
  regex.match(pattern, env.name)
  is_string(env.value)
  msg := sprintf("container <%v> env var <%v> matches credential pattern <%v> but uses a plain-text value; use secretKeyRef instead", [container.name, env.name, pattern])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  env := container.env[_]
  pattern := input.parameters.credentialEnvPatterns[_]
  regex.match(pattern, env.name)
  is_string(env.value)
  msg := sprintf("initContainer <%v> env var <%v> matches credential pattern <%v> but uses a plain-text value; use secretKeyRef instead", [container.name, env.name, pattern])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.ephemeralContainers[_]
  env := container.env[_]
  pattern := input.parameters.credentialEnvPatterns[_]
  regex.match(pattern, env.name)
  is_string(env.value)
  msg := sprintf("ephemeralContainer <%v> env var <%v> matches credential pattern <%v> but uses a plain-text value; use secretKeyRef instead", [container.name, env.name, pattern])
}
