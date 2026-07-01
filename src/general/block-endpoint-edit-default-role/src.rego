package k8sblockendpointeditdefaultrole

import future.keywords.contains
import future.keywords.if

violation contains ({"msg": msg}) if {
    input.review.object.metadata.name == "system:aggregate-to-edit"
    endpointRule(input.review.object.rules[_])
    msg := "ClusterRole system:aggregate-to-edit should not allow endpoint edit permissions. For k8s version < 1.22, the Cluster Role should be annotated with rbac.authorization.kubernetes.io/autoupdate=false to prevent autoreconciliation back to default permissions for this role."
}

endpointRule(rule) if {
    "endpoints" == rule.resources[_]
    hasEditVerb(rule.verbs)
}

hasEditVerb(verbs) if {
    "create" == verbs[_]
}

hasEditVerb(verbs) if {
    "patch" == verbs[_]
}

hasEditVerb(verbs) if {
    "update" == verbs[_]
}
