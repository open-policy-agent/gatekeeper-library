package requirednamespacequota

import rego.v1

# ✅ Test Case 1: Namespace has a ResourceQuota (should NOT violate)
test_namespace_with_quota if{
    test_input := {
        "review": {
            "kind": { "kind": "Namespace" },
            "object": { "metadata": { "name": "test-namespace" } },
            "related": [
                {
                    "kind": "ResourceQuota",
                    "metadata": { "namespace": "test-namespace" }
                }
            ]
        }
    }
    
    count(violation) == 0 with input as test_input
}

# ❌ Test Case 2: Namespace without a ResourceQuota (should violate)
test_namespace_without_quota if{
    test_input := {
        "review": {
            "kind": { "kind": "Namespace" },
            "object": { "metadata": { "name": "test-namespace" } },
            "related": []
        }
    }
    
    count(violation) > 0 with input as test_input
}

