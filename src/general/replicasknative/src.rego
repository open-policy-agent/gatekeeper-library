package k8sknativereplica

missing(obj, field) = true {
    not obj[field]
}

missing(obj, field) = true {
    obj[field] == ""
}

violation[{"msg": msg}] {
    service := input.review.object
    missing(service.spec.template.metadata.annotations, "autoscaling.knative.dev/maxScale")
    msg := sprintf("Knative service serving %v has no maxScale value defined", [service.metadata.name])
}

violation[{"msg": msg}] {
    service := input.review.object
    missing(service.spec.template.metadata, "annotations")
    msg := sprintf("Knative service serving %v has no annotations defined", [service.metadata.name])
}

violation[{"msg": msg}] {
    replicas := input.parameters.replicas
    service := input.review.object
    max_scale := service.spec.template.metadata.annotations["autoscaling.knative.dev/maxScale"]
    to_number(replicas) < to_number(max_scale)
    msg := sprintf("maxScale value %v cannot be greater than %v replicas", [max_scale, replicas])
}

violation[{"msg": msg}] {
    replicas := input.parameters.replicas
    service := input.review.object
    min_scale := service.spec.template.metadata.annotations["autoscaling.knative.dev/minScale"]
    to_number(replicas) < to_number(min_scale)
    msg := sprintf("minScale value %v cannot be greater than %v replicas", [min_scale, replicas])
}

violation[{"msg": msg}] {
    replicas := input.parameters.replicas
    service := input.review.object
    max_scale := service.spec.template.metadata.annotations["autoscaling.knative.dev/maxScale"]
    min_scale := service.spec.template.metadata.annotations["autoscaling.knative.dev/minScale"]
    to_number(max_scale) < to_number(min_scale)
    msg := sprintf("minScale value %v cannot be greater than %v maxScale", [min_scale, max_scale])
}

violation[{"msg": msg}] {
    replicas := input.parameters.replicas
    service := input.review.object
    initial_scale := service.spec.template.metadata.annotations["autoscaling.knative.dev/initialScale"]
    to_number(replicas) < to_number(initial_scale)
    msg := sprintf("intialScale value %v cannot be greater than %v replicas", [initial_scale, replicas])
}