---
id: ai-workload-policies
title: AI Workload Policies
sidebar_label: Overview
---

# AI Workload Policies

AI workload policy profiles group GPU governance policies by operational intent. Choose the profile closest to the workload, then tune constraint parameters, namespace matching, and image exemptions for the cluster.

## Choose a profile

| Profile | Bundle | Intended use | Included policies |
|---|---|---|---|
| GPU Safety | `gatekeeper-gpu-safety-policies` | Shared baseline for GPU placement, fairness, and resource declarations | GPU Node Targeting, GPU Resource Limits, GPU Workload Resources, Required GPU Toleration |
| Training | `gatekeeper-ai-training-policies` | Batch training, fine-tuning, research jobs, and other temporary GPU workloads | GPU Safety policies plus GPU Active Deadline and GPU Shared Memory |
| Inference | `gatekeeper-ai-inference-policies` | Long-running model serving and inference workloads | GPU Node Targeting, GPU Resource Limits, GPU Workload Resources, Required GPU Toleration |

## How the policies work together

The policies cover different parts of running a GPU workload:

1. **Scheduling eligibility:** Required GPU Toleration allows a pod onto tainted GPU nodes.
2. **Placement:** GPU Node Targeting selects the intended accelerator pool, product, or cost class.
3. **Fairness:** GPU Resource Limits prevents one container from reserving too many GPUs.
4. **Resource hygiene:** GPU Workload Resources keeps CPU, memory, and GPU declarations predictable.
5. **Training safeguards:** GPU Active Deadline bounds runtime, while GPU Shared Memory supports multiprocessing-heavy workloads.

Each profile identifies templates intended to be used together. After applying the selected templates, configure constraints for the label keys, taints, limits, namespaces, and exemptions used by the cluster.

## Policy guidance

### GPU Active Deadline

A training job can hang because of a bad training loop, stalled data loader, or abandoned experiment while continuing to reserve an expensive GPU. [GPU Active Deadline](./gpuactivedeadline.md) requires GPU pods to set `activeDeadlineSeconds` so Kubernetes eventually terminates them.

Use it for batch training, hyperparameter searches, CI jobs, temporary fine-tuning, and bounded notebook sessions. Set `maxActiveDeadlineSeconds` to cap runtime, or set it to `0` when the field must be present but each workload may choose its own deadline.

Avoid applying a short maximum to long-running inference services or persistent notebooks. Scope the constraint separately when training and serving workloads share a cluster.

### GPU Resource Limits

On a shared node, a typo or oversized request can reserve every available GPU and block other tenants. [GPU Resource Limits](./gpuresourcelimits.md) caps `nvidia.com/gpu` per container through `maxGpuPerContainer`.

Use it for multi-tenant clusters, cost-controlled GPU pools, and namespaces where workloads should consume only a portion of a node. This is a per-container limit, not a namespace quota.

Choose a value that still permits legitimate full-node and distributed training. Workloads with different allocation needs can use separately scoped constraints or image exemptions.

### GPU Workload Resources

A GPU can remain underutilized when its container lacks enough CPU for preprocessing or when incomplete memory declarations lead to poor placement and eviction. [GPU Workload Resources](./gpuworkloadresources.md) requires matching GPU requests and limits on GPU containers, matching memory requests and limits, and a CPU request.

Use it when predictable scheduling, bin packing, and capacity planning matter for training or inference. It also makes resource declarations more useful for cost attribution.

The memory and CPU requirements apply to non-exempt regular and init containers in a GPU pod. GPU request and limit matching also covers GPU-requesting ephemeral containers. Sidecars, init containers, service-mesh proxies, and monitoring agents may therefore need complete declarations or narrowly defined image exemptions.

### Required GPU Toleration

Clusters commonly taint dedicated GPU nodes to keep ordinary workloads away. A GPU pod without the corresponding toleration remains `Pending` even when accelerator capacity is available. [Required GPU Toleration](./requiredgputoleration.md) requires the taint key configured by `tolerationKey`.

Use it wherever GPU node pools are protected by taints. A toleration only permits scheduling onto a tainted node; it does not force the pod onto that node. Pair this policy with GPU Node Targeting when placement must be explicit.

### GPU Node Targeting

Clusters may offer several accelerator pools, such as L4, A100, H100, spot, reserved, training, or inference nodes. A GPU resource request asks for accelerator capacity, but labels determine which pool or product is acceptable. [GPU Node Targeting](./gpunodetargeting.md) requires a configured node label through `nodeSelector` or required node affinity.

Set `nodeLabelKey` to the pool or product label. Optionally set `nodeLabelValues` to restrict acceptable values; without values, the policy only requires the key to be present.

Kubernetes ORs the entries in required `nodeSelectorTerms`. Every term must preserve the configured GPU label requirement. Otherwise, one valid term and one broader term could pass policy while still allowing scheduling outside the intended GPU pool.

### GPU Shared Memory

PyTorch data loaders, NCCL communication, Ray workers, and other multiprocessing-heavy training workloads often need more shared memory than a container's default `/dev/shm`. Without it, jobs can fail with bus or shared-memory errors, hang, or perform poorly. [GPU Shared Memory](./gpusharedmemory.md) requires GPU containers to mount a memory-backed `emptyDir` at `/dev/shm`.

Use it for training workloads that rely on multiprocessing or inter-process communication. The policy evaluates regular and init containers that request GPUs.

Simple inference and single-process GPU workloads may not need additional shared memory. Keep this policy in the training profile or scope it to workloads that require it.

## Standalone policies

The following policies are available separately because they are not appropriate for every profile:

- [No Unsupported GPU](./nounsupportedgpu.md) requires GPU-requesting containers to declare `NVIDIA_VISIBLE_DEVICES`.
- [Required GPU Runtime Class](./requiredgpuruntimeclass.md) restricts GPU workloads to approved runtime classes.
