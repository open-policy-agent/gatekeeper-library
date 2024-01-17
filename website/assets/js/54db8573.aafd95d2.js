"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[9361],{9956:(e,n,i)=>{i.r(n),i.d(n,{assets:()=>m,contentTitle:()=>a,default:()=>p,frontMatter:()=>s,metadata:()=>o,toc:()=>c});var t=i(5893),r=i(1151);const s={id:"containerresourceratios",title:"Container Ratios"},a="Container Ratios",o={id:"validation/containerresourceratios",title:"Container Ratios",description:"Description",source:"@site/docs/validation/containerresourceratios.md",sourceDirName:"validation",slug:"/validation/containerresourceratios",permalink:"/gatekeeper-library/website/validation/containerresourceratios",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/containerresourceratios.md",tags:[],version:"current",frontMatter:{id:"containerresourceratios",title:"Container Ratios"},sidebar:"docs",previous:{title:"Container Requests",permalink:"/gatekeeper-library/website/validation/containerrequests"},next:{title:"Required Resources",permalink:"/gatekeeper-library/website/validation/containerresources"}},m={},c=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function l(e){const n={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,r.a)(),...e.components},{Details:i}=n;return i||function(e,n){throw new Error("Expected "+(n?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(n.h1,{id:"container-ratios",children:"Container Ratios"}),"\n",(0,t.jsx)(n.h2,{id:"description",children:"Description"}),"\n",(0,t.jsxs)(n.p,{children:["Sets a maximum ratio for container resource limits to requests.\n",(0,t.jsx)(n.a,{href:"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",children:"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"})]}),"\n",(0,t.jsx)(n.h2,{id:"template",children:"Template"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8scontainerratios\n  annotations:\n    metadata.gatekeeper.sh/title: "Container Ratios"\n    metadata.gatekeeper.sh/version: 1.0.1\n    description: >-\n      Sets a maximum ratio for container resource limits to requests.\n\n      https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sContainerRatios\n      validation:\n        openAPIV3Schema:\n          type: object\n          properties:\n            exemptImages:\n              description: >-\n                Any container that uses an image that matches an entry in this list will be excluded\n                from enforcement. Prefix-matching can be signified with `*`. For example: `my-image-*`.\n\n                It is recommended that users use the fully-qualified Docker image name (e.g. start with a domain name)\n                in order to avoid unexpectedly exempting images from an untrusted repository.\n              type: array\n              items:\n                type: string\n            ratio:\n              type: string\n              description: >-\n                The maximum allowed ratio of `resources.limits` to\n                `resources.requests` on a container.\n            cpuRatio:\n              type: string\n              description: >-\n                The maximum allowed ratio of `resources.limits.cpu` to\n                `resources.requests.cpu` on a container. If not specified,\n                equal to `ratio`.\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      rego: |\n        package k8scontainerratios\n\n        import data.lib.exempt_container.is_exempt\n\n        missing(obj, field) = true {\n          not obj[field]\n        }\n\n        missing(obj, field) = true {\n          obj[field] == ""\n        }\n\n        canonify_cpu(orig) = new {\n          is_number(orig)\n          new := orig * 1000\n        }\n\n        canonify_cpu(orig) = new {\n          not is_number(orig)\n          endswith(orig, "m")\n          new := to_number(replace(orig, "m", ""))\n        }\n\n        canonify_cpu(orig) = new {\n          not is_number(orig)\n          not endswith(orig, "m")\n          regex.match("^[0-9]+$", orig)\n          new := to_number(orig) * 1000\n        }\n\n        canonify_cpu(orig) = new {\n          not is_number(orig)\n          not endswith(orig, "m")\n          regex.match("^[0-9]+[.][0-9]+$", orig)\n          new := to_number(orig) * 1000\n        }\n\n        # 10 ** 21\n        mem_multiple("E") = 1000000000000000000000 { true }\n\n        # 10 ** 18\n        mem_multiple("P") = 1000000000000000000 { true }\n\n        # 10 ** 15\n        mem_multiple("T") = 1000000000000000 { true }\n\n        # 10 ** 12\n        mem_multiple("G") = 1000000000000 { true }\n\n        # 10 ** 9\n        mem_multiple("M") = 1000000000 { true }\n\n        # 10 ** 6\n        mem_multiple("k") = 1000000 { true }\n\n        # 10 ** 3\n        mem_multiple("") = 1000 { true }\n\n        # Kubernetes accepts millibyte precision when it probably shouldn\'t.\n        # https://github.com/kubernetes/kubernetes/issues/28741\n        # 10 ** 0\n        mem_multiple("m") = 1 { true }\n\n        # 1000 * 2 ** 10\n        mem_multiple("Ki") = 1024000 { true }\n\n        # 1000 * 2 ** 20\n        mem_multiple("Mi") = 1048576000 { true }\n\n        # 1000 * 2 ** 30\n        mem_multiple("Gi") = 1073741824000 { true }\n\n        # 1000 * 2 ** 40\n        mem_multiple("Ti") = 1099511627776000 { true }\n\n        # 1000 * 2 ** 50\n        mem_multiple("Pi") = 1125899906842624000 { true }\n\n        # 1000 * 2 ** 60\n        mem_multiple("Ei") = 1152921504606846976000 { true }\n\n        get_suffix(mem) = suffix {\n          not is_string(mem)\n          suffix := ""\n        }\n\n        get_suffix(mem) = suffix {\n          is_string(mem)\n          count(mem) > 0\n          suffix := substring(mem, count(mem) - 1, -1)\n          mem_multiple(suffix)\n        }\n\n        get_suffix(mem) = suffix {\n          is_string(mem)\n          count(mem) > 1\n          suffix := substring(mem, count(mem) - 2, -1)\n          mem_multiple(suffix)\n        }\n\n        get_suffix(mem) = suffix {\n          is_string(mem)\n          count(mem) > 1\n          not mem_multiple(substring(mem, count(mem) - 1, -1))\n          not mem_multiple(substring(mem, count(mem) - 2, -1))\n          suffix := ""\n        }\n\n        get_suffix(mem) = suffix {\n          is_string(mem)\n          count(mem) == 1\n          not mem_multiple(substring(mem, count(mem) - 1, -1))\n          suffix := ""\n        }\n\n        get_suffix(mem) = suffix {\n          is_string(mem)\n          count(mem) == 0\n          suffix := ""\n        }\n\n        canonify_mem(orig) = new {\n          is_number(orig)\n          new := orig * 1000\n        }\n\n        canonify_mem(orig) = new {\n          not is_number(orig)\n          suffix := get_suffix(orig)\n          raw := replace(orig, suffix, "")\n          regex.match("^[0-9]+(\\\\.[0-9]+)?$", raw)\n          new := to_number(raw) * mem_multiple(suffix)\n        }\n\n        violation[{"msg": msg}] {\n          general_violation[{"msg": msg, "field": "containers"}]\n        }\n\n        violation[{"msg": msg}] {\n          general_violation[{"msg": msg, "field": "initContainers"}]\n        }\n\n        # Ephemeral containers not checked as it is not possible to set field.\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          cpu_orig := container.resources.limits.cpu\n          not canonify_cpu(cpu_orig)\n          msg := sprintf("container <%v> cpu limit <%v> could not be parsed", [container.name, cpu_orig])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          mem_orig := container.resources.limits.memory\n          not canonify_mem(mem_orig)\n          msg := sprintf("container <%v> memory limit <%v> could not be parsed", [container.name, mem_orig])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          cpu_orig := container.resources.requests.cpu\n          not canonify_cpu(cpu_orig)\n          msg := sprintf("container <%v> cpu request <%v> could not be parsed", [container.name, cpu_orig])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          mem_orig := container.resources.requests.memory\n          not canonify_mem(mem_orig)\n          msg := sprintf("container <%v> memory request <%v> could not be parsed", [container.name, mem_orig])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          not container.resources\n          msg := sprintf("container <%v> has no resource limits", [container.name])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          not container.resources.limits\n          msg := sprintf("container <%v> has no resource limits", [container.name])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          missing(container.resources.limits, "cpu")\n          msg := sprintf("container <%v> has no cpu limit", [container.name])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          missing(container.resources.limits, "memory")\n          msg := sprintf("container <%v> has no memory limit", [container.name])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          not container.resources.requests\n          msg := sprintf("container <%v> has no resource requests", [container.name])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          missing(container.resources.requests, "cpu")\n          msg := sprintf("container <%v> has no cpu request", [container.name])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          missing(container.resources.requests, "memory")\n          msg := sprintf("container <%v> has no memory request", [container.name])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          cpu_limits_orig := container.resources.limits.cpu\n          cpu_limits := canonify_cpu(cpu_limits_orig)\n          cpu_requests_orig := container.resources.requests.cpu\n          cpu_requests := canonify_cpu(cpu_requests_orig)\n          cpu_ratio := object.get(input.parameters, "cpuRatio", input.parameters.ratio)\n          to_number(cpu_limits) > to_number(cpu_ratio) * to_number(cpu_requests)\n          msg := sprintf("container <%v> cpu limit <%v> is higher than the maximum allowed ratio of <%v>", [container.name, cpu_limits_orig, cpu_ratio])\n        }\n\n        general_violation[{"msg": msg, "field": field}] {\n          container := input.review.object.spec[field][_]\n          not is_exempt(container)\n          mem_limits_orig := container.resources.limits.memory\n          mem_requests_orig := container.resources.requests.memory\n          mem_limits := canonify_mem(mem_limits_orig)\n          mem_requests := canonify_mem(mem_requests_orig)\n          mem_ratio := input.parameters.ratio\n          to_number(mem_limits) > to_number(mem_ratio) * to_number(mem_requests)\n          msg := sprintf("container <%v> memory limit <%v> is higher than the maximum allowed ratio of <%v>", [container.name, mem_limits_orig, mem_ratio])\n        }\n      libs:\n        - |\n          package lib.exempt_container\n\n          is_exempt(container) {\n              exempt_images := object.get(object.get(input, "parameters", {}), "exemptImages", [])\n              img := container.image\n              exemption := exempt_images[_]\n              _matches_exemption(img, exemption)\n          }\n\n          _matches_exemption(img, exemption) {\n              not endswith(exemption, "*")\n              exemption == img\n          }\n\n          _matches_exemption(img, exemption) {\n              endswith(exemption, "*")\n              prefix := trim_suffix(exemption, "*")\n              startswith(img, prefix)\n          }\n\n'})}),"\n",(0,t.jsx)(n.h3,{id:"usage",children:"Usage"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresourceratios/template.yaml\n"})}),"\n",(0,t.jsx)(n.h2,{id:"examples",children:"Examples"}),"\n",(0,t.jsxs)(i,{children:[(0,t.jsx)("summary",{children:"memory-ratio-only"}),(0,t.jsxs)(i,{children:[(0,t.jsx)("summary",{children:"constraint"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sContainerRatios\nmetadata:\n  name: container-must-meet-ratio\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    ratio: "2"\n\n'})}),(0,t.jsx)(n.p,{children:"Usage"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresourceratios/samples/container-must-meet-ratio/constraint.yaml\n"})})]}),(0,t.jsxs)(i,{children:[(0,t.jsx)("summary",{children:"example-allowed"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: opa-disallowed\n  labels:\n    owner: me.agilebank.demo\nspec:\n  containers:\n    - name: opa\n      image: openpolicyagent/opa:0.9.2\n      args:\n        - "run"\n        - "--server"\n        - "--addr=localhost:8080"\n      resources:\n        limits:\n          cpu: "200m"\n          memory: "200Mi"\n        requests:\n          cpu: "100m"\n          memory: "100Mi"\n\n'})}),(0,t.jsx)(n.p,{children:"Usage"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresourceratios/samples/container-must-meet-ratio/example_allowed.yaml\n"})})]}),(0,t.jsxs)(i,{children:[(0,t.jsx)("summary",{children:"example-disallowed"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: opa-disallowed\n  labels:\n    owner: me.agilebank.demo\nspec:\n  containers:\n    - name: opa\n      image: openpolicyagent/opa:0.9.2\n      args:\n        - "run"\n        - "--server"\n        - "--addr=localhost:8080"\n      resources:\n        limits:\n          cpu: "800m"\n          memory: "2Gi"\n        requests:\n          cpu: "100m"\n          memory: "100Mi"\n\n'})}),(0,t.jsx)(n.p,{children:"Usage"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresourceratios/samples/container-must-meet-ratio/example_disallowed.yaml\n"})})]})]}),"\n",(0,t.jsxs)(i,{children:[(0,t.jsx)("summary",{children:"memory-and-cpu-ratios"}),(0,t.jsxs)(i,{children:[(0,t.jsx)("summary",{children:"constraint"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sContainerRatios\nmetadata:\n  name: container-must-meet-memory-and-cpu-ratio\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    ratio: "1"\n    cpuRatio: "10"\n\n'})}),(0,t.jsx)(n.p,{children:"Usage"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresourceratios/samples/container-must-meet-memory-and-cpu-ratio/constraint.yaml\n"})})]}),(0,t.jsxs)(i,{children:[(0,t.jsx)("summary",{children:"example-allowed"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: opa-allowed\n  labels:\n    owner: me.agilebank.demo\nspec:\n  containers:\n    - name: opa\n      image: openpolicyagent/opa:0.9.2\n      args:\n        - "run"\n        - "--server"\n        - "--addr=localhost:8080"\n      resources:\n        limits:\n          cpu: "4"\n          memory: "2Gi"\n        requests:\n          cpu: "1"\n          memory: "2Gi"\n\n'})}),(0,t.jsx)(n.p,{children:"Usage"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresourceratios/samples/container-must-meet-memory-and-cpu-ratio/example_allowed.yaml\n"})})]}),(0,t.jsxs)(i,{children:[(0,t.jsx)("summary",{children:"example-disallowed"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: opa-disallowed\n  labels:\n    owner: me.agilebank.demo\nspec:\n  containers:\n    - name: opa\n      image: openpolicyagent/opa:0.9.2\n      args:\n        - "run"\n        - "--server"\n        - "--addr=localhost:8080"\n      resources:\n        limits:\n          cpu: "4"\n          memory: "2Gi"\n        requests:\n          cpu: "100m"\n          memory: "2Gi"\n\n'})}),(0,t.jsx)(n.p,{children:"Usage"}),(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/containerresourceratios/samples/container-must-meet-memory-and-cpu-ratio/example_disallowed.yaml\n"})})]})]})]})}function p(e={}){const{wrapper:n}={...(0,r.a)(),...e.components};return n?(0,t.jsx)(n,{...e,children:(0,t.jsx)(l,{...e})}):l(e)}},1151:(e,n,i)=>{i.d(n,{Z:()=>o,a:()=>a});var t=i(7294);const r={},s=t.createContext(r);function a(e){const n=t.useContext(s);return t.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function o(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(r):e.components||r:a(e.components),t.createElement(s.Provider,{value:n},e.children)}}}]);