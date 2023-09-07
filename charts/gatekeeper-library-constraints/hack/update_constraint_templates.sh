#!/bin/bash

FILES=(
  "allowed-repos.yaml                             :  general/allowedrepos"
  "psp-automount-service-account-token-pod.yaml   :  general/automount-serviceaccount-token"
  "block-endpoint-edit-default-role.yaml          :  general/block-endpoint-edit-default-role"
  "block-load-balancer.yaml                       :  general/block-loadbalancer-services"
  "block-node-port.yaml                           :  general/block-nodeport-services"
  "block-wildcard-ingress.yaml                    :  general/block-wildcard-ingress"
  "container-limits.yaml                          :  general/containerlimits"
  "container-requests.yaml                        :  general/containerrequests"
  "container-ratios.yaml                          :  general/containerresourceratios"
  "required-resources.yaml                        :  general/containerresources"
  "disallow-anonymous.yaml                        :  general/disallowanonymous"
  "disallowed-repos.yaml                          :  general/disallowedrepos"
  "disallowed-tags.yaml                           :  general/disallowedtags"
  "container-ephemeral-storage-limit.yaml         :  general/ephemeralstoragelimit"
  "external-ips.yaml                              :  general/externalip"
  "horizontal-pod-autoscaler.yaml                 :  general/horizontalpodautoscaler"
  "https-only.yaml                                :  general/httpsonly"
  "image-digests.yaml                             :  general/imagedigests"
  "no-update-service-account.yaml                 :  general/noupdateserviceaccount"
  "pod-disruption-budget.yaml                     :  general/poddisruptionbudget"
  "replica-limits.yaml                            :  general/replicalimits"
  "required-annotations.yaml                      :  general/requiredannotations"
  "required-labels.yaml                           :  general/requiredlabels"
  "required-probes.yaml                           :  general/requiredprobes"
  "storageclass.yaml                              :  general/storageclass"
  "unique-ingress-host.yaml                       :  general/uniqueingresshost"
  "unique-service-selector.yaml                   :  general/uniqueserviceselector"
  "verify-deprecated-api.yaml                     :  general/verifydeprecatedapi"
  "psp-allow-privilege-escalation-container.yaml  :  pod-security-policy/allow-privilege-escalation"
  "psp-apparmor.yaml                              :  pod-security-policy/apparmor"
  "psp-capabilities.yaml                          :  pod-security-policy/capabilities"
  "psp-flex-volumes.yaml                          :  pod-security-policy/flexvolume-drivers"
  "psp-forbidden-sysctls.yaml                     :  pod-security-policy/forbidden-sysctls"
  "psp-fsgroup.yaml                               :  pod-security-policy/fsgroup"
  "psp-host-filesystem.yaml                       :  pod-security-policy/host-filesystem"
  "psp-host-namespace.yaml                        :  pod-security-policy/host-namespaces"
  "psp-host-networking-ports.yaml                 :  pod-security-policy/host-network-ports"
  "psp-privileged-container.yaml                  :  pod-security-policy/privileged-containers"
  "psp-proc-mount.yaml                            :  pod-security-policy/proc-mount"
  "psp-read-only-root-filesystem.yaml             :  pod-security-policy/read-only-root-filesystem"
  "psp-seccomp.yaml                               :  pod-security-policy/seccomp"
  "psp-selinux-v2.yaml                            :  pod-security-policy/selinux"
  "psp-allowed-users.yaml                         :  pod-security-policy/users"
  "psp-volume-types.yaml                          :  pod-security-policy/volumes"
)

for line in "${FILES[@]}"; do
    DESTINATION=$(echo "${line%%:*}" | xargs)
    SOURCE=$(echo "${line##*:}" | xargs)

    URL="https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/$SOURCE/template.yaml"

    echo -e "Downloading Gatekeeper Library constraint template from master branch:\n${URL}\n"

    echo "# ${URL}" > ../crds/"${DESTINATION}"

    if ! curl --silent --retry-all-errors --fail --location "${URL}" >> ../../gatekeeper-library-constraint-templates/templates/"${DESTINATION}"; then
      echo -e "Failed to download ${URL}!"
      exit 1
    fi
done

exit
