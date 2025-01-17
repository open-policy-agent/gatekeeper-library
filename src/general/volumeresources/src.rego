package k8svolumerequests

violation[{"msg": msg}] {
    vols := input.review.object.spec.volumes[_]
    emptydir := vols.emptyDir
    not has_key(emptydir, "sizeLimit")
    msg := sprintf("Volume '%v' is not allowed, do not have set sizelimit", [vols.name])
}

violation[{"msg": msg}] {
    vols := input.review.object.spec.volumes[_]
    emptydir_orig := vols.emptyDir.sizeLimit
    size := canonify_size(emptydir_orig)
    max_size_orig := input.parameters.volumesizelimit
    max_size := canonify_size(max_size_orig)
    size > max_size
    msg := sprintf("volume <%v> size limit <%v> is higher than the maximum allowed of <%v>", [vols.name, emptydir_orig, max_size_orig])
}

has_key(object, key) {
    type_name(object[key])
}

size_multiple("E") = 1000000000000000000000

# 10 ** 18
size_multiple("P") = 1000000000000000000

# 10 ** 15
size_multiple("T") = 1000000000000000

# 10 ** 12
size_multiple("G") = 1000000000000

# 10 ** 9
size_multiple("M") = 1000000000

# 10 ** 6
size_multiple("k") = 1000000

# 10 ** 3
size_multiple("") = 1000

# Kubernetes accepts millibyte precision when it probably shouldn't.
# https://github.com/kubernetes/kubernetes/issues/28741
# 10 ** 0
size_multiple("m") = 1

# 1000 * 2 ** 10
size_multiple("Ki") = 1024000

# 1000 * 2 ** 20
size_multiple("Mi") = 1048576000

# 1000 * 2 ** 30
size_multiple("Gi") = 1073741824000

# 1000 * 2 ** 40
size_multiple("Ti") = 1099511627776000

# 1000 * 2 ** 50
size_multiple("Pi") = 1125899906842624000

# 1000 * 2 ** 60
size_multiple("Ei") = 1152921504606846976000

canonify_size(orig) = new {
	is_number(orig)
	new := orig * 1000
}

get_suffix(size) = suffix {
	is_string(size)
	count(size) > 0
	suffix := substring(size, count(size) - 1, -1)
	size_multiple(suffix)
}

get_suffix(size) = suffix {
	is_string(size)
	count(size) > 1
	suffix := substring(size, count(size) - 2, -1)
	size_multiple(suffix)
}

get_suffix(size) = suffix {
	is_string(size)
	count(size) > 1
	not size_multiple(substring(size, count(size) - 1, -1))
	not size_multiple(substring(size, count(size) - 2, -1))
	suffix := ""
}

get_suffix(size) = suffix {
	is_string(size)
	count(size) == 1
	not size_multiple(substring(size, count(size) - 1, -1))
	suffix := ""
}

get_suffix(size) = suffix {
	is_string(size)
	count(size) == 0
	suffix := ""
}

canonify_size(orig) = new {
	is_number(orig)
	new := orig * 1000
}

canonify_size(orig) = new {
	not is_number(orig)
	suffix := get_suffix(orig)
	raw := replace(orig, suffix, "")
	regex.match("^[0-9]+(\\.[0-9]+)?$", raw)
	new := to_number(raw) * size_multiple(suffix)
}