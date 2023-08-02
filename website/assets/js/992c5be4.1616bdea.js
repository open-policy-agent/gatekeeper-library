"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[3118],{3905:(e,n,a)=>{a.d(n,{Zo:()=>c,kt:()=>b});var t=a(7294);function i(e,n,a){return n in e?Object.defineProperty(e,n,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[n]=a,e}function r(e,n){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var t=Object.getOwnPropertySymbols(e);n&&(t=t.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),a.push.apply(a,t)}return a}function o(e){for(var n=1;n<arguments.length;n++){var a=null!=arguments[n]?arguments[n]:{};n%2?r(Object(a),!0).forEach((function(n){i(e,n,a[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):r(Object(a)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(a,n))}))}return e}function l(e,n){if(null==e)return{};var a,t,i=function(e,n){if(null==e)return{};var a,t,i={},r=Object.keys(e);for(t=0;t<r.length;t++)a=r[t],n.indexOf(a)>=0||(i[a]=e[a]);return i}(e,n);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(t=0;t<r.length;t++)a=r[t],n.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(i[a]=e[a])}return i}var s=t.createContext({}),p=function(e){var n=t.useContext(s),a=n;return e&&(a="function"==typeof e?e(n):o(o({},n),e)),a},c=function(e){var n=p(e.components);return t.createElement(s.Provider,{value:n},e.children)},m="mdxType",d={inlineCode:"code",wrapper:function(e){var n=e.children;return t.createElement(t.Fragment,{},n)}},u=t.forwardRef((function(e,n){var a=e.components,i=e.mdxType,r=e.originalType,s=e.parentName,c=l(e,["components","mdxType","originalType","parentName"]),m=p(a),u=i,b=m["".concat(s,".").concat(u)]||m[u]||d[u]||r;return a?t.createElement(b,o(o({ref:n},c),{},{components:a})):t.createElement(b,o({ref:n},c))}));function b(e,n){var a=arguments,i=n&&n.mdxType;if("string"==typeof e||i){var r=a.length,o=new Array(r);o[0]=u;var l={};for(var s in n)hasOwnProperty.call(n,s)&&(l[s]=n[s]);l.originalType=e,l[m]="string"==typeof e?e:i,o[1]=l;for(var p=2;p<r;p++)o[p]=a[p];return t.createElement.apply(null,o)}return t.createElement.apply(null,a)}u.displayName="MDXCreateElement"},2450:(e,n,a)=>{a.r(n),a.d(n,{assets:()=>s,contentTitle:()=>o,default:()=>d,frontMatter:()=>r,metadata:()=>l,toc:()=>p});var t=a(7462),i=(a(7294),a(3905));const r={id:"capabilities",title:"Capabilities"},o="Capabilities",l={unversionedId:"validation/capabilities",id:"validation/capabilities",title:"Capabilities",description:"Description",source:"@site/docs/validation/capabilities.md",sourceDirName:"validation",slug:"/validation/capabilities",permalink:"/gatekeeper-library/website/validation/capabilities",draft:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/capabilities.md",tags:[],version:"current",frontMatter:{id:"capabilities",title:"Capabilities"},sidebar:"docs",previous:{title:"App Armor",permalink:"/gatekeeper-library/website/validation/apparmor"},next:{title:"FlexVolumes",permalink:"/gatekeeper-library/website/validation/flexvolume-drivers"}},s={},p=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}],c={toc:p},m="wrapper";function d(e){let{components:n,...a}=e;return(0,i.kt)(m,(0,t.Z)({},c,a,{components:n,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"capabilities"},"Capabilities"),(0,i.kt)("h2",{id:"description"},"Description"),(0,i.kt)("p",null,"Controls Linux capabilities on containers. Corresponds to the ",(0,i.kt)("inlineCode",{parentName:"p"},"allowedCapabilities")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"requiredDropCapabilities")," fields in a PodSecurityPolicy. For more information, see ",(0,i.kt)("a",{parentName:"p",href:"https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities"},"https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities")),(0,i.kt)("h2",{id:"template"},"Template"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8spspcapabilities\n  annotations:\n    metadata.gatekeeper.sh/title: "Capabilities"\n    metadata.gatekeeper.sh/version: 1.0.0\n    description: >-\n      Controls Linux capabilities on containers. Corresponds to the\n      `allowedCapabilities` and `requiredDropCapabilities` fields in a\n      PodSecurityPolicy. For more information, see\n      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sPSPCapabilities\n      validation:\n        # Schema for the `parameters` field\n        openAPIV3Schema:\n          type: object\n          description: >-\n            Controls Linux capabilities on containers. Corresponds to the\n            `allowedCapabilities` and `requiredDropCapabilities` fields in a\n            PodSecurityPolicy. For more information, see\n            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities\n          properties:\n            exemptImages:\n              description: >-\n                Any container that uses an image that matches an entry in this list will be excluded\n                from enforcement. Prefix-matching can be signified with `*`. For example: `my-image-*`.\n\n                It is recommended that users use the fully-qualified Docker image name (e.g. start with a domain name)\n                in order to avoid unexpectedly exempting images from an untrusted repository.\n              type: array\n              items:\n                type: string\n            allowedCapabilities:\n              type: array\n              description: "A list of Linux capabilities that can be added to a container."\n              items:\n                type: string\n            requiredDropCapabilities:\n              type: array\n              description: "A list of Linux capabilities that are required to be dropped from a container."\n              items:\n                type: string\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      rego: |\n        package capabilities\n\n        import data.lib.exempt_container.is_exempt\n\n        violation[{"msg": msg}] {\n          container := input.review.object.spec.containers[_]\n          not is_exempt(container)\n          has_disallowed_capabilities(container)\n          msg := sprintf("container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])\n        }\n\n        violation[{"msg": msg}] {\n          container := input.review.object.spec.containers[_]\n          not is_exempt(container)\n          missing_drop_capabilities(container)\n          msg := sprintf("container <%v> is not dropping all required capabilities. Container must drop all of %v or \\"ALL\\"", [container.name, input.parameters.requiredDropCapabilities])\n        }\n\n\n\n        violation[{"msg": msg}] {\n          container := input.review.object.spec.initContainers[_]\n          not is_exempt(container)\n          has_disallowed_capabilities(container)\n          msg := sprintf("init container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])\n        }\n\n        violation[{"msg": msg}] {\n          container := input.review.object.spec.initContainers[_]\n          not is_exempt(container)\n          missing_drop_capabilities(container)\n          msg := sprintf("init container <%v> is not dropping all required capabilities. Container must drop all of %v or \\"ALL\\"", [container.name, input.parameters.requiredDropCapabilities])\n        }\n\n\n\n        violation[{"msg": msg}] {\n          container := input.review.object.spec.ephemeralContainers[_]\n          not is_exempt(container)\n          has_disallowed_capabilities(container)\n          msg := sprintf("ephemeral container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])\n        }\n\n        violation[{"msg": msg}] {\n          container := input.review.object.spec.ephemeralContainers[_]\n          not is_exempt(container)\n          missing_drop_capabilities(container)\n          msg := sprintf("ephemeral container <%v> is not dropping all required capabilities. Container must drop all of %v or \\"ALL\\"", [container.name, input.parameters.requiredDropCapabilities])\n        }\n\n\n        has_disallowed_capabilities(container) {\n          allowed := {c | c := lower(input.parameters.allowedCapabilities[_])}\n          not allowed["*"]\n          capabilities := {c | c := lower(container.securityContext.capabilities.add[_])}\n\n          count(capabilities - allowed) > 0\n        }\n\n        missing_drop_capabilities(container) {\n          must_drop := {c | c := lower(input.parameters.requiredDropCapabilities[_])}\n          all := {"all"}\n          dropped := {c | c := lower(container.securityContext.capabilities.drop[_])}\n\n          count(must_drop - dropped) > 0\n          count(all - dropped) > 0\n        }\n\n        get_default(obj, param, _default) = out {\n          out = obj[param]\n        }\n\n        get_default(obj, param, _default) = out {\n          not obj[param]\n          not obj[param] == false\n          out = _default\n        }\n      libs:\n        - |\n          package lib.exempt_container\n\n          is_exempt(container) {\n              exempt_images := object.get(object.get(input, "parameters", {}), "exemptImages", [])\n              img := container.image\n              exemption := exempt_images[_]\n              _matches_exemption(img, exemption)\n          }\n\n          _matches_exemption(img, exemption) {\n              not endswith(exemption, "*")\n              exemption == img\n          }\n\n          _matches_exemption(img, exemption) {\n              endswith(exemption, "*")\n              prefix := trim_suffix(exemption, "*")\n              startswith(img, prefix)\n          }\n\n')),(0,i.kt)("h3",{id:"usage"},"Usage"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/capabilities/template.yaml\n")),(0,i.kt)("h2",{id:"examples"},"Examples"),(0,i.kt)("details",null,(0,i.kt)("summary",null,"capabilities"),(0,i.kt)("blockquote",null,(0,i.kt)("details",null,(0,i.kt)("summary",null,"constraint"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sPSPCapabilities\nmetadata:\n  name: capabilities-demo\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n    namespaces:\n      - "default"\n  parameters:\n    allowedCapabilities: ["something"]\n    requiredDropCapabilities: ["must_drop"]\n\n')),(0,i.kt)("p",null,"Usage"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/capabilities/samples/capabilities-demo/constraint.yaml\n"))),(0,i.kt)("details",null,(0,i.kt)("summary",null,"example-disallowed"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: v1\nkind: Pod\nmetadata:\n  name: opa-disallowed\n  labels:\n    owner: me.agilebank.demo\nspec:\n  containers:\n    - name: opa\n      image: openpolicyagent/opa:0.9.2\n      args:\n        - "run"\n        - "--server"\n        - "--addr=localhost:8080"\n      securityContext:\n        capabilities:\n          add: ["disallowedcapability"]\n      resources:\n        limits:\n          cpu: "100m"\n          memory: "30Mi"\n')),(0,i.kt)("p",null,"Usage"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/capabilities/samples/capabilities-demo/example_disallowed.yaml\n"))),(0,i.kt)("details",null,(0,i.kt)("summary",null,"example-allowed"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: v1\nkind: Pod\nmetadata:\n  name: opa-allowed\n  labels:\n    owner: me.agilebank.demo\nspec:\n  containers:\n    - name: opa\n      image: openpolicyagent/opa:0.9.2\n      args:\n        - "run"\n        - "--server"\n        - "--addr=localhost:8080"\n      securityContext:\n        capabilities:\n          add: ["something"]\n          drop: ["must_drop", "another_one"]\n      resources:\n        limits:\n          cpu: "100m"\n          memory: "30Mi"\n\n')),(0,i.kt)("p",null,"Usage"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/capabilities/samples/capabilities-demo/example_allowed.yaml\n"))),(0,i.kt)("details",null,(0,i.kt)("summary",null,"disallowed-ephemeral"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: v1\nkind: Pod\nmetadata:\n  name: opa-disallowed\n  labels:\n    owner: me.agilebank.demo\nspec:\n  ephemeralContainers:\n    - name: opa\n      image: openpolicyagent/opa:0.9.2\n      args:\n        - "run"\n        - "--server"\n        - "--addr=localhost:8080"\n      securityContext:\n        capabilities:\n          add: ["disallowedcapability"]\n      resources:\n        limits:\n          cpu: "100m"\n          memory: "30Mi"\n\n')),(0,i.kt)("p",null,"Usage"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/capabilities/samples/capabilities-demo/disallowed_ephemeral.yaml\n"))))))}d.isMDXComponent=!0}}]);