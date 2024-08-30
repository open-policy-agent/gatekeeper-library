"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[1459],{87:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>p,contentTitle:()=>o,default:()=>m,frontMatter:()=>r,metadata:()=>i,toc:()=>l});var s=t(5893),a=t(1151);const r={id:"host-network-ports",title:"Host Networking Ports"},o="Host Networking Ports",i={id:"validation/host-network-ports",title:"Host Networking Ports",description:"Description",source:"@site/docs/validation/host-network-ports.md",sourceDirName:"validation",slug:"/validation/host-network-ports",permalink:"/gatekeeper-library/website/validation/host-network-ports",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/host-network-ports.md",tags:[],version:"current",frontMatter:{id:"host-network-ports",title:"Host Networking Ports"},sidebar:"docs",previous:{title:"Host Namespace",permalink:"/gatekeeper-library/website/validation/host-namespaces"},next:{title:"Privileged Container",permalink:"/gatekeeper-library/website/validation/privileged-containers"}},p={},l=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function c(e){const n={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,a.a)(),...e.components},{Details:t}=n;return t||function(e,n){throw new Error("Expected "+(n?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(n.h1,{id:"host-networking-ports",children:"Host Networking Ports"}),"\n",(0,s.jsx)(n.h2,{id:"description",children:"Description"}),"\n",(0,s.jsxs)(n.p,{children:["Controls usage of host network namespace by pod containers. HostNetwork verification happens without exception for exemptImages. Specific ports must be specified. Corresponds to the ",(0,s.jsx)(n.code,{children:"hostNetwork"})," and ",(0,s.jsx)(n.code,{children:"hostPorts"})," fields in a PodSecurityPolicy. For more information, see ",(0,s.jsx)(n.a,{href:"https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces",children:"https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces"})]}),"\n",(0,s.jsx)(n.h2,{id:"template",children:"Template"}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8spsphostnetworkingports\n  annotations:\n    metadata.gatekeeper.sh/title: "Host Networking Ports"\n    metadata.gatekeeper.sh/version: 1.1.3\n    description: >-\n      Controls usage of host network namespace by pod containers. HostNetwork verification happens without exception for exemptImages. Specific\n      ports must be specified. Corresponds to the `hostNetwork` and\n      `hostPorts` fields in a PodSecurityPolicy. For more information, see\n      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sPSPHostNetworkingPorts\n      validation:\n        # Schema for the `parameters` field\n        openAPIV3Schema:\n          type: object\n          description: >-\n            Controls usage of host network namespace by pod containers. HostNetwork verification happens without exception for exemptImages. Specific\n            ports must be specified. Corresponds to the `hostNetwork` and\n            `hostPorts` fields in a PodSecurityPolicy. For more information, see\n            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces\n          properties:\n            exemptImages:\n              description: >-\n                Any container that uses an image that matches an entry in this list will be excluded\n                from enforcement. Prefix-matching can be signified with `*`. For example: `my-image-*`.\n\n                It is recommended that users use the fully-qualified Docker image name (e.g. start with a domain name)\n                in order to avoid unexpectedly exempting images from an untrusted repository.\n              type: array\n              items:\n                type: string\n            hostNetwork:\n              description: "Determines if the policy allows the use of HostNetwork in the pod spec."\n              type: boolean\n            min:\n              description: "The start of the allowed port range, inclusive."\n              type: integer\n            max:\n              description: "The end of the allowed port range, inclusive."\n              type: integer\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      code:\n      - engine: K8sNativeValidation\n        source:\n          variables:\n          - name: containers\n            expression: \'has(variables.anyObject.spec.containers) ? variables.anyObject.spec.containers : []\'\n          - name: initContainers\n            expression: \'has(variables.anyObject.spec.initContainers) ? variables.anyObject.spec.initContainers : []\'\n          - name: ephemeralContainers\n            expression: \'has(variables.anyObject.spec.ephemeralContainers) ? variables.anyObject.spec.ephemeralContainers : []\'\n          - name: exemptImagePrefixes\n            expression: |\n              !has(variables.params.exemptImages) ? [] :\n                variables.params.exemptImages.filter(image, image.endsWith("*")).map(image, string(image).replace("*", ""))\n          - name: exemptImageExplicit\n            expression: |\n              !has(variables.params.exemptImages) ? [] : \n                variables.params.exemptImages.filter(image, !image.endsWith("*"))\n          - name: exemptImages\n            expression: |\n              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,\n                container.image in variables.exemptImageExplicit ||\n                variables.exemptImagePrefixes.exists(exemption, string(container.image).startsWith(exemption)))\n          - name: badContainers\n            expression: |\n              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,\n                !(container.image in variables.exemptImages) && has(container.ports) &&\n                (\n                  (container.ports.all(port, has(port.hostPort) && has(variables.params.min) && port.hostPort < variables.params.min)) ||\n                  (container.ports.all(port, has(port.hostPort) && has(variables.params.max) && port.hostPort > variables.params.max))\n                )\n              )\n          - name: isUpdate\n            expression: has(request.operation) && request.operation == "UPDATE"\n          - name: hostNetworkAllowed\n            expression: has(variables.params.hostNetwork) && variables.params.hostNetwork\n          - name: hostNetworkEnabled\n            expression: has(variables.anyObject.spec.hostNetwork) && variables.anyObject.spec.hostNetwork\n          - name: hostNetworkViolation\n            expression: variables.hostNetworkEnabled && !variables.hostNetworkAllowed\n          validations:\n          - expression: \'variables.isUpdate || size(variables.badContainers) == 0\'\n            messageExpression: \'"The specified hostNetwork and hostPort are not allowed, pod: " + variables.anyObject.metadata.name\'\n          - expression: variables.isUpdate || !variables.hostNetworkViolation\n            messageExpression: \'"The specified hostNetwork and hostPort are not allowed, pod: " + variables.anyObject.metadata.name\'\n      - engine: Rego\n        source:\n          rego: |\n            package k8spsphostnetworkingports\n\n            import data.lib.exclude_update.is_update\n            import data.lib.exempt_container.is_exempt\n\n            violation[{"msg": msg, "details": {}}] {\n                # spec.hostNetwork field is immutable.\n                not is_update(input.review)\n\n                input_share_hostnetwork(input.review.object)\n                msg := sprintf("The specified hostNetwork and hostPort are not allowed, pod: %v. Allowed values: %v", [input.review.object.metadata.name, input.parameters])\n            }\n\n            input_share_hostnetwork(o) {\n                not input.parameters.hostNetwork\n                o.spec.hostNetwork\n            }\n\n            input_share_hostnetwork(_) {\n                hostPort := input_containers[_].ports[_].hostPort\n                hostPort < input.parameters.min\n            }\n\n            input_share_hostnetwork(_) {\n                hostPort := input_containers[_].ports[_].hostPort\n                hostPort > input.parameters.max\n            }\n\n            input_containers[c] {\n                c := input.review.object.spec.containers[_]\n                not is_exempt(c)\n            }\n\n            input_containers[c] {\n                c := input.review.object.spec.initContainers[_]\n                not is_exempt(c)\n            }\n\n            input_containers[c] {\n                c := input.review.object.spec.ephemeralContainers[_]\n                not is_exempt(c)\n            }\n          libs:\n            - |\n              package lib.exclude_update\n\n              is_update(review) {\n                  review.operation == "UPDATE"\n              }\n            - |\n              package lib.exempt_container\n\n              is_exempt(container) {\n                  exempt_images := object.get(object.get(input, "parameters", {}), "exemptImages", [])\n                  img := container.image\n                  exemption := exempt_images[_]\n                  _matches_exemption(img, exemption)\n              }\n\n              _matches_exemption(img, exemption) {\n                  not endswith(exemption, "*")\n                  exemption == img\n              }\n\n              _matches_exemption(img, exemption) {\n                  endswith(exemption, "*")\n                  prefix := trim_suffix(exemption, "*")\n                  startswith(img, prefix)\n              }\n\n'})}),"\n",(0,s.jsx)(n.h3,{id:"usage",children:"Usage"}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/template.yaml\n"})}),"\n",(0,s.jsx)(n.h2,{id:"examples",children:"Examples"}),"\n",(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"port-range-with-host-network-allowed"}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"constraint"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sPSPHostNetworkingPorts\nmetadata:\n  name: psp-host-network-ports\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    hostNetwork: true\n    min: 80\n    max: 9000\n'})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/constraint.yaml\n"})})]}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"out-of-range"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-networking-ports-disallowed\n  labels:\n    app: nginx-host-networking-ports\nspec:\n  hostNetwork: true\n  containers:\n  - name: nginx\n    image: nginx\n    ports:\n    - containerPort: 9001\n      hostPort: 9001\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/port_range_block_host_network/example_disallowed_out_of_range_host_network_true.yaml\n"})})]}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"example-allowed"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-networking-ports-allowed\n  labels:\n    app: nginx-host-networking-ports\nspec:\n  containers:\n  - name: nginx\n    image: nginx\n    ports:\n    - containerPort: 9000\n      hostPort: 80\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_in_range.yaml\n"})})]}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"out-of-range-ephemeral"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-networking-ports-disallowed\n  labels:\n    app: nginx-host-networking-ports\nspec:\n  hostNetwork: true\n  ephemeralContainers:\n  - name: nginx\n    image: nginx\n    ports:\n    - containerPort: 9001\n      hostPort: 9001\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/disallowed_ephemeral.yaml\n"})})]}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"no-ports-specified"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-networking-ports-disallowed\n  labels:\n    app: nginx-host-networking-ports\nspec:\n  hostNetwork: true\n  containers:\n  - name: nginx\n    image: nginx\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_no_ports.yaml\n"})})]})]}),"\n",(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"host-network-forbidden"}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"constraint"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sPSPHostNetworkingPorts\nmetadata:\n  name: psp-host-network\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    hostNetwork: false\n\n'})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/block_host_network/constraint.yaml\n"})})]}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"hostnetwork-true"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-network-true\nspec:\n  hostNetwork: true\n  containers:\n  - name: nginx\n    image: nginx\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_no_ports_host_network_true.yaml\n"})})]}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"hostnetwork-false"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-network-false\nspec:\n  hostNetwork: false\n  containers:\n  - name: nginx\n    image: nginx\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_no_ports_host_network_false.yaml\n"})})]})]}),"\n",(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"port-range-with-host-network-forbidden"}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"constraint"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sPSPHostNetworkingPorts\nmetadata:\n  name: psp-host-network-ports\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    hostNetwork: false\n    min: 80\n    max: 9000\n\n'})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/port_range_block_host_network/constraint.yaml\n"})})]}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"out-of-range-and-host-network-true"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-networking-ports-disallowed\n  labels:\n    app: nginx-host-networking-ports\nspec:\n  hostNetwork: true\n  containers:\n  - name: nginx\n    image: nginx\n    ports:\n    - containerPort: 9001\n      hostPort: 9001\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/port_range_block_host_network/example_disallowed_out_of_range_host_network_true.yaml\n"})})]}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"in-range-host-network-false"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-networking-ports-allowed\n  labels:\n    app: nginx-host-networking-ports\nspec:\n  containers:\n  - name: nginx\n    image: nginx\n    ports:\n    - containerPort: 9000\n      hostPort: 80\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_in_range.yaml\n"})})]}),(0,s.jsxs)(t,{children:[(0,s.jsx)("summary",{children:"disallowed-ephemeral"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-networking-ports-disallowed\n  labels:\n    app: nginx-host-networking-ports\nspec:\n  hostNetwork: true\n  ephemeralContainers:\n  - name: nginx\n    image: nginx\n    ports:\n    - containerPort: 9001\n      hostPort: 9001\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/disallowed_ephemeral.yaml\n"})})]})]})]})}function m(e={}){const{wrapper:n}={...(0,a.a)(),...e.components};return n?(0,s.jsx)(n,{...e,children:(0,s.jsx)(c,{...e})}):c(e)}},1151:(e,n,t)=>{t.d(n,{Z:()=>i,a:()=>o});var s=t(7294);const a={},r=s.createContext(a);function o(e){const n=s.useContext(r);return s.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function i(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(a):e.components||a:o(e.components),s.createElement(r.Provider,{value:n},e.children)}}}]);