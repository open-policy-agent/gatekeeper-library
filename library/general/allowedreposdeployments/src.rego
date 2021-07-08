package container_deny_repo

import data.lib.core
import data.lib.pods

policyID := "P2001"

violation[msg] {
  pods.containers[container]
  satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
  not any(satisfied)
  msg := core.format_with_id(sprintf("%s/%s/%s/%s: Images must not come from other then only-this-repo", [core.kind, core.name, container.image, container.name]), policyID)
}