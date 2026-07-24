# Forbidden Sysctls security context policy

The forbidden sysctls constraint allows one to limit the set of kernel parameters that can be modified by pods. This is accomplished by specifying a combination of allowed and forbidden sysctls using either of two parameters: `allowedSysctls` and `forbiddenSysctls`.

## Parameters

`allowedSysctls`: A list of explicitly allowed sysctls. Any sysctl not in this list will be considered forbidden. '*' and trailing wildcards are supported. If unspecified, no limitations are made by this parameter.

`forbiddenSysctls`: A list of explicitly denied sysctls. Any sysctl in this list will be considered forbidden. '*' and trailing wildcards are supported. If unspecified, no limitations are made by this parameter.

## Examples

```yaml
parameters:
  allowedSysctls: ['*']
  forbiddenSysctls:
    - kernel.msg*
    - net.core.somaxconn
```

```yaml
parameters:
  allowedSysctls:
    - kernel.shm_rmid_forced
    - net.ipv4.ip_local_port_range
    - net.ipv4.tcp_syncookies
    - net.ipv4.ping_group_range
  forbiddenSysctls: []
```

*Note*: `forbiddenSysctls` takes precedence, such that an explicitly forbidden sysctl is still forbidden even if it appears in `allowedSysctls` as well. However in practice, such overlap between the rules should be avoided.

## References

* [Using sysctls in a Kubernetes Cluster](https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/)
* [Kubernetes API Reference - Sysctl](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#sysctl-v1-core)