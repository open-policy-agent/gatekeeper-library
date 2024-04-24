package k8svolumerequests

test_input_no_sizeLimit {
    input := {"review": container([{"emptyDir": {}, "name": "test"}]), "parameters": {"volumesizelimit": "3Gi"}}
    results := violation with input as input
    count(results) == 1
}

test_input_with_sizeLimit_lower {
    input := {"review": container([vol("2Gi", "test")]), "parameters": {"volumesizelimit": "3Gi"}}
    results := violation with input as input
    count(results) == 0
}

test_input_with_sizeLimit_higher {
    input := {"review": container([vol("5Gi", "test")]), "parameters": {"volumesizelimit": "3Gi"}}
    results := violation with input as input
    count(results) == 1
}

test_input_with_sizeLimit_muti_higher {
    input := {"review": container([vol("5Gi", "test"), vol("1Gi", "test1")]), "parameters": {"volumesizelimit": "3Gi"}}
    results := violation with input as input
    count(results) == 1
}

container(volumes) = output {
    output = {"object": {"spec": {"template": {"spec": {"volumes": volumes}}}}}
}

vol(size, name) = out {
    out = {
        "emptyDir": {"sizeLimit": size},
        "name": name
    }
}
