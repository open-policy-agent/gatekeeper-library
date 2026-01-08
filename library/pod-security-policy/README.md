# Pod Security Standards

This library provides Gatekeeper policies that implement the [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/). These standards define three profiles that cover the security spectrum:

- **Privileged**: Unrestricted policy, providing the widest possible level of permissions.
- **Baseline**: Minimally restrictive policy which prevents known privilege escalations. Allows the default (minimally specified) Pod configuration.
- **Restricted**: Heavily restricted policy, following current Pod hardening best practices.

> **Note:** The profiles are **cumulative** - the Restricted profile includes all policies from the Baseline profile, plus additional restrictions.

These policies were originally based on the deprecated [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) but have been updated to align with the modern Pod Security Standards.

An administrator can control the following by deploying the corresponding Gatekeeper constraint and constraint templates:

## Baseline Profile

These policies prevent known privilege escalations and are recommended as the minimum security configuration for most workloads.

| Control Aspect                                    | Gatekeeper Constraint and Constraint Template            |
|---------------------------------------------------|----------------------------------------------------------|
| Running of privileged containers                  | [privileged-containers](privileged-containers)           |
| Usage of host namespaces                          | [host-namespaces](host-namespaces)                       |
| Usage of host networking and ports                | [host-network-ports](host-network-ports)                 |
| Usage of the host filesystem                      | [host-filesystem](host-filesystem)                       |
| Linux capabilities                                | [capabilities](capabilities)                             |
| The SELinux context of the container              | [selinux](selinux)                                       |
| The allowed Proc mount types for the container    | [proc-mount](proc-mount)                                 |
| The AppArmor profile used by containers           | [apparmor](apparmor)                                     |
| The seccomp profile used by containers            | [seccompv2](seccompv2)                                   |
| The sysctl profile used by containers             | [forbidden-sysctls](forbidden-sysctls)                   |

## Restricted Profile

These policies provide additional hardening on top of the Baseline profile. Deploy these **in addition to** the Baseline policies for maximum security.

| Control Aspect                                    | Gatekeeper Constraint and Constraint Template            |
|---------------------------------------------------|----------------------------------------------------------|
| Restricting escalation to root privileges         | [allow-privilege-escalation](allow-privilege-escalation) |
| Approved list of flex-volume drivers              | [flexvolume-drivers](flexvolume-drivers)                 |
| Allocating an FSGroup that owns the Pod's volumes | [fsgroup](fsgroup)                                       |
| Requiring the use of a read only root file system | [read-only-root-filesystem](read-only-root-filesystem)   |
| The user and group IDs of the container           | [users](users)                                           |
| Usage of volume types                             | [volumes](volumes)                                       |
