---
id: pspintro
title: Introduction
---

# pod-security-policies

This repo contains common policies needed in Pod Security Policy but implemented as Constraints and Constraint Templates with Gatekeeper.

A [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) is a cluster-level resource that controls security
sensitive aspects of the pod specification. The `PodSecurityPolicy` objects define a set of conditions that a pod must run with in order to be accepted into the system, as well as defaults for the related fields.

An administrator can control the following by setting the field in PSP or by deploying the corresponding Gatekeeper constraint and constraint templates:

| Control Aspect                                    | Field Names in PSP                                                          | Gatekeeper Constraint and Constraint Template            |
|---------------------------------------------------|-----------------------------------------------------------------------------|----------------------------------------------------------|
| Running of privileged containers                  | `privileged`                                                                | [privileged-containers](validation/privileged-containers)           |
| Usage of host namespaces                          | `hostPID`, `hostIPC`                                                        | [host-namespaces](validation/host-namespaces)                       |
| Usage of host networking and ports                | `hostNetwork`, `hostPorts`                                                  | [host-network-ports](validation/host-network-ports)                 |
| Usage of volume types                             | `volumes`                                                                   | [volumes](validation/volumes)                                       |
| Usage of the host filesystem                      | `allowedHostPaths`                                                          | [host-filesystem](validation/host-filesystem)                       |
| Approved list of flex-volume drivers              | `allowedFlexVolumes`                                                        | [flexvolume-drivers](validation/flexvolume-drivers)                 |
| Requiring the use of a read only root file system | `readOnlyRootFilesystem`                                                    | [read-only-root-filesystem](validation/read-only-root-filesystem)   |
| The user and group IDs of the container           | `runAsUser`, `runAsGroup`, `supplementalGroups`, `fsgroup`                  | [users](validation/users)                                           |
| Restricting escalation to root privileges         | `allowPrivilegeEscalation`, `defaultAllowPrivilegeEscalation`               | [allow-privilege-escalation](validation/allow-privilege-escalation) |
| Linux capabilities                                | `defaultAddCapabilities`, `requiredDropCapabilities`, `allowedCapabilities` | [capabilities](validation/capabilities)                             |
| The SELinux context of the container              | `seLinux`                                                                   | [seLinux](validation/selinux)                                       |
| The allowed Proc mount types for the container    | `allowedProcMountTypes`                                                     | [proc-mount](validation/proc-mount)                                 |
| The AppArmor profile used by containers           | annotations                                                                 | [apparmor](validation/apparmor)                                     |
| The seccomp profile used by containers            | annotations                                                                 | [seccomp](validation/seccomp)                                       |
| The sysctl profile used by containers             | `forbiddenSysctls`,`allowedUnsafeSysctls`                                   | [forbidden-sysctls](validation/forbidden-sysctls)                   |

