# StorageClass

The `StorageClass` constraint blocks the creation of PVCs or StatefulSets 
where the specified storage class doesn't exist on the cluster, or that no
storage class at all is specified.

This policy helps prevent workloads from getting stuck indefinitely waiting
for a storage class to provision the persistent storage that will never 
happen. This often causes users to get confused as to why their pods are stuck
pending, and requires deleting the StatefulSet and any PVCs it has created along
with redeploying the workload in order to fix. Blocking it up front makes it
much easier to fix before there is a mess to clean up.

**WARNING** This constraint only functions properly
on gatekeeper version 3.9 or above.

