package noupdateserviceaccount

# Pod
pod_spec(sa_name) = spec {
    spec = {
        "serviceAccountName": sa_name,
    }
}

pod(sa_name) = obj {
    obj = {
        "kind": "Pod",
        "spec": pod_spec(sa_name),
    }
}

test_deny_pod {
    inp := {
        "review": update(pod("sa1"), pod("sa2"), {}),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    result == policy_violation
}

# ReplicationController
rc(sa_name) = obj {
    obj = {
        "kind": "ReplicationController",
        "spec": {
            "template": {
                "spec": pod_spec(sa_name),
            }
        }
    }
}

test_deny_rc {
    inp := {
        "review": update(rc("sa1"), rc("sa2"), {}),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    result == policy_violation
}

# ReplicaSet
rs(sa_name) = obj {
    obj = {
        "kind": "ReplicaSet",
        "spec": {
            "template": {
                "spec": pod_spec(sa_name),
            }
        }
    }
}

test_deny_rs {
    inp := {
        "review": update(rs("sa1"), rs("sa2"), {}),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    result == policy_violation
}

# Deployment
deploy(sa_name) = obj {
    obj = {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": pod_spec(sa_name),
            }
        }
    }
}

test_deny_deploy {
    inp := {
        "review": update(deploy("sa1"), deploy("sa2"), {}),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    result == policy_violation
}

# StatefulSet
ss(sa_name) = obj {
    obj = {
        "kind": "StatefulSet",
        "spec": {
            "template": {
                "spec": pod_spec(sa_name),
            }
        }
    }
}

test_deny_ss {
    inp := {
        "review": update(ss("sa1"), ss("sa2"), {}),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    result == policy_violation
}

# DaemonSet
ds(sa_name) = obj {
    obj = {
        "kind": "DaemonSet",
        "spec": {
            "template": {
                "spec": pod_spec(sa_name),
            }
        }
    }
}

test_deny_ds {
    inp := {
        "review": update(ds("sa1"), ds("sa2"), {}),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    result == policy_violation
}

# Job
job(sa_name) = obj {
    obj = {
        "kind": "Job",
        "spec": {
            "template": {
                "spec": pod_spec(sa_name),
            }
        }
    }
}

test_deny_job {
    inp := {
        "review": update(job("sa1"), job("sa2"), {}),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    result == policy_violation
}

# CronJob
cronjob(sa_name) = obj {
    obj = {
        "kind": "CronJob",
        "spec": {
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": pod_spec(sa_name),
                    }
                }
            }
        }
    }
}

test_deny_cronjob {
    inp := {
        "review": update(cronjob("sa1"), cronjob("sa2"), {}),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    result == policy_violation
}

# Allow unrelated modification
test_allow_unrelated {
    a := deploy("sa")
    b := {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {
                    "serviceAccountName": "sa",
                    "containers": [{"name": "newcontainer"}],
                }
            }
        }
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
test_allow_create {
    inp := {
        "review": create(deploy("sa1")),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    count(result) == 0
}

test_allow_delete {
    inp := {
        "review": delete(deploy("sa1")),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    count(result) == 0
}

# Allowlist users and groups
test_allow_users {
    inp := {
        "review": update(deploy("sa1"), deploy("sa2"), {"username": "myuser"}),
        "parameters": allow(["myuser"], []),
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    count(result) == 0
}

test_allow_groups {
    inp := {
        "review": update(deploy("sa1"), deploy("sa2"), {"groups": ["mygroup"]}),
        "parameters": allow([], ["mygroup"]),
    }
    result := violation with input as inp
    trace(sprintf("result: %v", [result]))
    count(result) == 0
}

# Malformed
test_deny_missing_old {
    inp := {
        "review": update({}, pod("sa"), {}),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("%v", [result]))
    result == missing_old_violation
}

test_deny_missing_new {
    inp := {
        "review": update(pod("sa"), {}, {}),
        "parameters": {},
    }
    result := violation with input as inp
    trace(sprintf("%v", [result]))
    result == missing_new_violation
}

# Other helpers

update(old, new, user) = output {
    output = {
        "operation": "UPDATE",
        "oldObject": old,
        "object": new,
        "userInfo": user,
    }
}

create(obj) = output {
    output = {
        "operation": "CREATE",
        "oldObject": null,
        "object": obj,
        "userInfo": {},
    }
}

delete(obj) = output {
    output = {
        "operation": "DELETE",
        "oldObject": obj,
        "object": null,
        "userInfo": {},
    }
}

allow(users, groups) = params {
    params = {
        "allowedUsers": users,
        "allowedGroups": groups,
    }
}

missing_old_violation[{"msg": msg}] {
    msg := "missing serviceAccountName field in oldObject under review"
}

missing_new_violation[{"msg": msg}] {
    msg := "missing serviceAccountName field in object under review"
}

policy_violation[{"msg": msg}] {
    msg := "user does not have permission to modify serviceAccountName"
}
