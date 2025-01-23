package noupdateserviceaccount

import rego.v1

# Pod
pod_spec(sa_name) := {"serviceAccountName": sa_name}

pod(sa_name) := {
	"kind": "Pod",
	"spec": pod_spec(sa_name),
}

test_deny_pod if {
	inp := {
		"review": update(pod("sa1"), pod("sa2"), {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	result == policy_violation
}

# ReplicationController
rc(sa_name) := {
	"kind": "ReplicationController",
	"spec": {"template": {"spec": pod_spec(sa_name)}},
}

test_deny_rc if {
	inp := {
		"review": update(rc("sa1"), rc("sa2"), {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	result == policy_violation
}

# ReplicaSet
rs(sa_name) := {
	"kind": "ReplicaSet",
	"spec": {"template": {"spec": pod_spec(sa_name)}},
}

test_deny_rs if {
	inp := {
		"review": update(rs("sa1"), rs("sa2"), {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	result == policy_violation
}

# Deployment
deploy(sa_name) := {
	"kind": "Deployment",
	"spec": {"template": {"spec": pod_spec(sa_name)}},
}

test_deny_deploy if {
	inp := {
		"review": update(deploy("sa1"), deploy("sa2"), {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	result == policy_violation
}

# StatefulSet
ss(sa_name) := {
	"kind": "StatefulSet",
	"spec": {"template": {"spec": pod_spec(sa_name)}},
}

test_deny_ss if {
	inp := {
		"review": update(ss("sa1"), ss("sa2"), {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	result == policy_violation
}

# DaemonSet
ds(sa_name) := {
	"kind": "DaemonSet",
	"spec": {"template": {"spec": pod_spec(sa_name)}},
}

test_deny_ds if {
	inp := {
		"review": update(ds("sa1"), ds("sa2"), {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	result == policy_violation
}

# Job
job(sa_name) := {
	"kind": "Job",
	"spec": {"template": {"spec": pod_spec(sa_name)}},
}

test_deny_job if {
	inp := {
		"review": update(job("sa1"), job("sa2"), {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	result == policy_violation
}

# CronJob
cronjob(sa_name) := {
	"kind": "CronJob",
	"spec": {"jobTemplate": {"spec": {"template": {"spec": pod_spec(sa_name)}}}},
}

test_deny_cronjob if {
	inp := {
		"review": update(cronjob("sa1"), cronjob("sa2"), {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	result == policy_violation
}

# Allow unrelated modification
test_allow_unrelated if {
	a := deploy("sa")
	b := {
		"kind": "Deployment",
		"spec": {"template": {"spec": {
			"serviceAccountName": "sa",
			"containers": [{"name": "newcontainer"}],
		}}},
	}
	inp := {
		"review": update(a, b, {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	count(result) == 0
}

# Allow create and delete
test_allow_create if {
	inp := {
		"review": create(deploy("sa1")),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	count(result) == 0
}

test_allow_delete if {
	inp := {
		"review": delete(deploy("sa1")),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	count(result) == 0
}

# Allowlist users and groups
test_allow_users if {
	inp := {
		"review": update(deploy("sa1"), deploy("sa2"), {"username": "myuser"}),
		"parameters": allow(["myuser"], []),
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	count(result) == 0
}

test_allow_groups if {
	inp := {
		"review": update(deploy("sa1"), deploy("sa2"), {"groups": ["mygroup"]}),
		"parameters": allow([], ["mygroup"]),
	}
	result := violation with input as inp
	trace(sprintf("result: %v", [result]))
	count(result) == 0
}

# Malformed
test_deny_missing_old if {
	inp := {
		"review": update({}, pod("sa"), {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("%v", [result]))
	result == missing_old_violation
}

test_deny_missing_new if {
	inp := {
		"review": update(pod("sa"), {}, {}),
		"parameters": {},
	}
	result := violation with input as inp
	trace(sprintf("%v", [result]))
	result == missing_new_violation
}

# Other helpers

update(old, new, user) := {
	"operation": "UPDATE",
	"oldObject": old,
	"object": new,
	"userInfo": user,
}

create(obj) := {
	"operation": "CREATE",
	"oldObject": null,
	"object": obj,
	"userInfo": {},
}

delete(obj) := {
	"operation": "DELETE",
	"oldObject": obj,
	"object": null,
	"userInfo": {},
}

allow(users, groups) := {
	"allowedUsers": users,
	"allowedGroups": groups,
}

missing_old_violation contains {"msg": "missing serviceAccountName field in oldObject under review"}

missing_new_violation contains {"msg": "missing serviceAccountName field in object under review"}

policy_violation contains {"msg": "user does not have permission to modify serviceAccountName"}
