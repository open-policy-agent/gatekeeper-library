package k8sdisallowanonymous

test_blank_subject_clusterrolebinding {
    inp := {"review": clusterrolebinding([{}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 0
}

test_non_anonymous_user_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "user-1", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 0
}

test_anonymous_user_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 1
}

test_anonymous_user_clusterrolebinding_no_param {
    inp := {"review": clusterrolebinding([{"name": "system:anonymous", "kind": "User"}], "role-2")}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_role_anonymous_user_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_subjects_anonymous_user_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:anonymous", "kind": "User"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_role_multiple_subjects_anonymous_user_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:anonymous", "kind": "User"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_role_multiple_subjects_anonymous_user_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:anonymous", "kind": "User"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-3"]}}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_multiple_role_multiple_subjects_anonymous_user_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:anonymous", "kind": "User"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_unauthenticated_group_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 1
}

test_unauthenticated_group_clusterrolebinding_no_param {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}], "role-2")}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_role_unauthenticated_group_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_subjects_unauthenticated_group_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_role_multiple_subjects_unauthenticated_group_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_role_multiple_subjects_unauthenticated_group_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-3"]}}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_multiple_role_multiple_subjects_unauthenticated_group_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_subjects_mix_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 2
}

test_allowed_role_multiple_subjects_mix_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_role_multiple_subjects_mix_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-3"]}}
    results := violation with input as inp
    count(results) == 2
}

test_allowed_multiple_role_multiple_subjects_mix_clusterrolebinding {
    inp := {"review": clusterrolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_blank_subject_rolebinding {
    inp := {"review": rolebinding([{}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 0
}

test_non_anonymous_rolebinding {
    inp := {"review": rolebinding([{"name": "user-1", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 0
}

test_anonymous_user_rolebinding {
    inp := {"review": rolebinding([{"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 1
}

test_anonymous_user_rolebinding_no_param {
    inp := {"review": rolebinding([{"name": "system:anonymous", "kind": "User"}], "role-2")}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_role_anonymous_user_rolebinding {
    inp := {"review": rolebinding([{"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_subjects_anonymous_user_rolebinding {
    inp := {"review": rolebinding([{"name": "system:anonymous", "kind": "User"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_role_multiple_subjects_anonymous_user_rolebinding {
    inp := {"review": rolebinding([{"name": "system:anonymous", "kind": "User"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_role_multiple_subjects_anonymous_user_rolebinding {
    inp := {"review": rolebinding([{"name": "system:anonymous", "kind": "User"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-3"]}}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_multiple_role_multiple_subjects_anonymous_user_rolebinding {
    inp := {"review": rolebinding([{"name": "system:anonymous", "kind": "User"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_unauthenticated_group_rolebinding_no_param {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}], "role-2")}
    results := violation with input as inp
    count(results) == 1
}

test_unauthenticated_group_rolebinding {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_role_unauthenticated_group_rolebinding {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_subjects_unauthenticated_group_rolebinding {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_role_multiple_subjects_unauthenticated_group_rolebinding {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_role_multiple_subjects_unauthenticated_group_rolebinding {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-3"]}}
    results := violation with input as inp
    count(results) == 1
}

test_allowed_multiple_role_multiple_subjects_unauthenticated_group_rolebinding {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:authenticated", "kind": "Group"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_subjects_mix_rolebinding {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-1"]}}
    results := violation with input as inp
    count(results) == 2
}

test_allowed_role_multiple_subjects_mix_rolebinding {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

test_multiple_role_multiple_subjects_mix_rolebinding {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-3"]}}
    results := violation with input as inp
    count(results) == 2
}

test_allowed_multiple_role_multiple_subjects_mix_rolebinding {
    inp := {"review": rolebinding([{"name": "system:unauthenticated", "kind": "Group"}, {"name": "system:anonymous", "kind": "User"}], "role-2"), "parameters": {"allowedRoles": ["role-1", "role-2"]}}
    results := violation with input as inp
    count(results) == 0
}

authenticated_rolebinding := rolebinding([{"name": "system:authenticated", "kind": "Group"}], "role-2")

test_authenticated_with_disallow_authenticated_true {
    inp := {"review": authenticated_rolebinding, "parameters": { "allowedRoles": [], "disallowAuthenticated": true }}
    results := violation with input as inp
    count(results) == 1
}

test_authenticated_with_disallow_authenticated_false {
    inp := {"review": authenticated_rolebinding, "parameters": { "allowedRoles": [], "disallowAuthenticated": false }}
    results := violation with input as inp
    count(results) == 0
}

test_authenticated_with_disallow_authenticated_undefined {
    inp := {"review": authenticated_rolebinding, "parameters": { "allowedRoles": [] }}
    results := violation with input as inp
    count(results) == 0
}

clusterrolebinding(subjects, roleref_name) = {
  "object": {
    "kind": "ClusterRoleBinding",
    "metadata": {
      "name": "cluster-role-binding"
    },
    "roleRef": {
      "apiGroup": "rbac.authorization.k8s.io",
      "kind": "ClusterRole",
      "name": roleref_name
    },
    "subjects": subjects
  }
}

rolebinding(subjects, roleref_name) = {
  "object": {
    "kind": "RoleBinding",
    "metadata": {
      "name": "role-binding",
      "namespace": "namespace-1"
    },
    "roleRef": {
      "apiGroup": "rbac.authorization.k8s.io",
      "kind": "ClusterRole",
      "name": roleref_name
    },
    "subjects": subjects
  }
}
