package k8sallowedreposv2

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not image_matches(container.image, input.parameters.allowedImages)
  msg := sprintf("container <%v> has an invalid image <%v>, allowed images are %v", [container.name, container.image, input.parameters.allowedImages])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  not image_matches(container.image, input.parameters.allowedImages)
  msg := sprintf("initContainer <%v> has an invalid image <%v>, allowed images are %v", [container.name, container.image, input.parameters.allowedImages])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.ephemeralContainers[_]
  not image_matches(container.image, input.parameters.allowedImages)
  msg := sprintf("ephemeralContainer <%v> has an invalid image <%v>, allowed images are %v", [container.name, container.image, input.parameters.allowedImages])
}

image_matches(image, images) {
  i_image := images[_]  # Iterate through all images in the allowed list
  not endswith(i_image, "*")  # Check for exact match if the image does not end with *
  i_image == image
}

image_matches(image, images) {
  i_image := images[_]  # Iterate through all images in the allowed list
  endswith(i_image, "*")  # Check for prefix match if the image ends with *
  prefix := trim_suffix(i_image, "*")
  startswith(image, prefix)
}
