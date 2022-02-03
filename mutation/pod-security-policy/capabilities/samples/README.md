# Capabilities

This library example demonstrates the [`defaultAddCapabilities`](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities) in Pod Security Policies.

There are two variations of this example:
1. `Assign`: Overrides each containers' security context capabilities with the provided list in `spec.parameters.assign.value`.
1. `ModifySet`: Appends `spec.parameters.values.fromList` to each containers' security context capabilities. `ModifySet` requires Gatekeeper v3.7.0 and later.

For more information, please see [Gatekeeper mutation docs](https://open-policy-agent.github.io/gatekeeper/website/docs/mutation).