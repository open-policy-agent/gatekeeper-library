package k8suniqueingresshost

import rego.v1

test_no_data if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules1, "extensions/v1beta1"), "extensions")}
	results := violation with input as inp
	count(results) == 0
}

test_identical if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules1, "extensions/v1beta1"), "extensions")}
	inv := inventory_data([ingress("my-ingress", "prod", my_rules1, "extensions/v1beta1")])
	trace(sprintf("%v", [inv]))

	results := violation with input as inp with data.inventory as inv
	trace(sprintf("%v", [results]))

	count(results) == 0
}

test_collision if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules1, "extensions/v1beta1"), "extensions")}
	inv := inventory_data([ingress("my-ingress", "prod2", my_rules1, "extensions/v1beta1")])
	results := violation with input as inp with data.inventory as inv
	count(results) == 1
}

test_collision_with_multiple if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules3, "extensions/v1beta1"), "extensions")}
	inv := inventory_data([ingress("my-ingress", "prod2", my_rules1, "extensions/v1beta1"), ingress("my-ingress1", "prod2", my_rules2, "extensions/v1beta1")])
	results := violation with input as inp with data.inventory as inv
	count(results) == 2
}

test_no_collision if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules1, "extensions/v1beta1"), "extensions")}
	inv := inventory_data([ingress("my-ingress", "prod2", my_rules2, "extensions/v1beta1")])
	results := violation with input as inp with data.inventory as inv
	count(results) == 0
}

test_no_collision_with_multiple if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules4, "extensions/v1beta1"), "extensions")}
	inv := inventory_data([ingress("my-ingress", "prod2", my_rules1, "extensions/v1beta1"), ingress("my-ingress", "prod3", my_rules2, "extensions/v1beta1")])
	results := violation with input as inp with data.inventory as inv
	count(results) == 0
}

test_no_collision_with_multiple_apis if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules4, "networking.k8s.io/v1beta1"), "networking.k8s.io")}
	inv := inventory_data2([ingress("my-ingress", "prod2", my_rules1, "networking.k8s.io/v1beta1"), ingress("my-ingress", "prod3", my_rules2, "networking.k8s.io/v1beta1")])
	results := violation with input as inp with data.inventory as inv
	count(results) == 0
}

test_collision_with_multiple_apis if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules3, "networking.k8s.io/v1beta1"), "networking.k8s.io")}
	inv := inventory_data2([ingress("my-ingress", "prod2", my_rules1, "networking.k8s.io/v1beta1"), ingress("my-ingress", "prod3", my_rules2, "networking.k8s.io/v1beta1")])
	results := violation with input as inp with data.inventory as inv
	count(results) == 2
}

test_no_collision_with_multiple_bad_review_apis if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules1, "app/v1beta1"), "app")}
	inv := inventory_data([ingress("my-ingress", "prod2", my_rules1, "extensions/v1beta1"), ingress("my-ingress", "prod3", my_rules2, "extensions/v1beta1")])
	results := violation with input as inp with data.inventory as inv
	count(results) == 0
}

test_no_collision_with_multiple_bad_review_apis2 if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules1, "test.extensions/v1beta1"), "test.extensions")}
	inv := inventory_data([ingress("my-ingress", "prod2", my_rules1, "extensions/v1beta1"), ingress("my-ingress", "prod3", my_rules2, "extensions/v1beta1")])
	results := violation with input as inp with data.inventory as inv
	count(results) == 0
}

test_collision_with_multiple_apis_mixed if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules1, "networking.k8s.io/v1beta1"), "networking.k8s.io")}
	inv := inventory_data([ingress("my-ingress", "prod2", my_rules1, "extensions/v1beta1"), ingress("my-ingress", "prod3", my_rules2, "extensions/v1beta1")])
	results := violation with input as inp with data.inventory as inv
	count(results) == 1
}

test_no_collision_with_multiple_apis_slash if {
	inp := {"review": review(ingress("my-ingress", "prod", my_rules1, "networking.k8s.io/v1beta1"), "networking.k8s.io")}
	inv := inventory_data1([ingress("my-ingress", "prod2", my_rules1, "extensions.something.io/v1beta1"), ingress("my-ingress", "prod3", my_rules2, "extensions.something.io/v1beta1")])
	results := violation with input as inp with data.inventory as inv
	count(results) == 0
}

review(ing, group) := {
	"kind": {
		"kind": "Ingress",
		"version": "v1beta1",
		"group": group,
	},
	"namespace": ing.metadata.namespace,
	"name": ing.metadata.name,
	"object": ing,
}

my_rule(host) := {
	"host": host,
	"http": {"paths": [{"backend": {"serviceName": "nginx", "servicePort": 80}}]},
}

my_rules1 := [my_rule("a.abc.com")]

my_rules2 := [my_rule("a1.abc.com")]

my_rules3 := [
	my_rule("a.abc.com"),
	my_rule("a1.abc.com"),
]

my_rules4 := [
	my_rule("a2.abc.com"),
	my_rule("a3.abc.com"),
]

ingress(name, ns, rules, apiversion) := {
	"kind": "Ingress",
	"apiVersion": apiversion,
	"metadata": {
		"name": name,
		"namespace": ns,
	},
	"spec": {"rules": rules},
}

inventory_data(ingresses) := out if {
	namespaces := {ns | ns = ingresses[_].metadata.namespace}
	out = {"namespace": {ns: {"extensions/v1beta1": {"Ingress": flatten_by_name(ingresses, ns)}} |
		ns := namespaces[_]
	}}
}

inventory_data1(ingresses) := out if {
	namespaces := {ns | ns = ingresses[_].metadata.namespace}
	out = {"namespace": {ns: {"extensions.something.io/v1beta1": {"Ingress": flatten_by_name(ingresses, ns)}} |
		ns := namespaces[_]
	}}
}

inventory_data2(ingresses) := out if {
	namespaces := {ns | ns = ingresses[_].metadata.namespace}
	out = {"namespace": {ns: {"networking.k8s.io/v1beta1": {"Ingress": flatten_by_name(ingresses, ns)}} |
		ns := namespaces[_]
	}}
}

flatten_by_name(ingresses, ns) := {o.metadata.name: o |
	some o in ingresses
	o.metadata.namespace == ns
}
