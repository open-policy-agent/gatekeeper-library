"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[266],{8710:(e,s,n)=>{n.r(s),n.d(s,{assets:()=>d,contentTitle:()=>a,default:()=>p,frontMatter:()=>i,metadata:()=>r,toc:()=>o});var t=n(5893),l=n(1151);const i={id:"forbidden-sysctls",title:"Forbidden Sysctls"},a="Forbidden Sysctls",r={id:"validation/forbidden-sysctls",title:"Forbidden Sysctls",description:"Description",source:"@site/docs/validation/forbidden-sysctls.md",sourceDirName:"validation",slug:"/validation/forbidden-sysctls",permalink:"/gatekeeper-library/website/validation/forbidden-sysctls",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/forbidden-sysctls.md",tags:[],version:"current",frontMatter:{id:"forbidden-sysctls",title:"Forbidden Sysctls"},sidebar:"docs",previous:{title:"FlexVolumes",permalink:"/gatekeeper-library/website/validation/flexvolume-drivers"},next:{title:"FS Group",permalink:"/gatekeeper-library/website/validation/fsgroup"}},d={},o=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function c(e){const s={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,l.a)(),...e.components},{Details:n}=s;return n||function(e,s){throw new Error("Expected "+(s?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(s.h1,{id:"forbidden-sysctls",children:"Forbidden Sysctls"}),"\n",(0,t.jsx)(s.h2,{id:"description",children:"Description"}),"\n",(0,t.jsxs)(s.p,{children:["Controls the ",(0,t.jsx)(s.code,{children:"sysctl"})," profile used by containers. Corresponds to the ",(0,t.jsx)(s.code,{children:"allowedUnsafeSysctls"})," and ",(0,t.jsx)(s.code,{children:"forbiddenSysctls"})," fields in a PodSecurityPolicy. When specified, any sysctl not in the ",(0,t.jsx)(s.code,{children:"allowedSysctls"})," parameter is considered to be forbidden. The ",(0,t.jsx)(s.code,{children:"forbiddenSysctls"})," parameter takes precedence over the ",(0,t.jsx)(s.code,{children:"allowedSysctls"})," parameter. For more information, see ",(0,t.jsx)(s.a,{href:"https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/",children:"https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/"})]}),"\n",(0,t.jsx)(s.h2,{id:"template",children:"Template"}),"\n",(0,t.jsx)(s.pre,{children:(0,t.jsx)(s.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8spspforbiddensysctls\n  annotations:\n    metadata.gatekeeper.sh/title: "Forbidden Sysctls"\n    metadata.gatekeeper.sh/version: 1.1.3\n    description: >-\n      Controls the `sysctl` profile used by containers. Corresponds to the\n      `allowedUnsafeSysctls` and `forbiddenSysctls` fields in a PodSecurityPolicy.\n      When specified, any sysctl not in the `allowedSysctls` parameter is considered to be forbidden.\n      The `forbiddenSysctls` parameter takes precedence over the `allowedSysctls` parameter.\n      For more information, see https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sPSPForbiddenSysctls\n      validation:\n        # Schema for the `parameters` field\n        openAPIV3Schema:\n          type: object\n          description: >-\n            Controls the `sysctl` profile used by containers. Corresponds to the\n            `allowedUnsafeSysctls` and `forbiddenSysctls` fields in a PodSecurityPolicy.\n            When specified, any sysctl not in the `allowedSysctls` parameter is considered to be forbidden.\n            The `forbiddenSysctls` parameter takes precedence over the `allowedSysctls` parameter.\n            For more information, see https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/\n          properties:\n            allowedSysctls:\n              type: array\n              description: "An allow-list of sysctls. `*` allows all sysctls not listed in the `forbiddenSysctls` parameter."\n              items:\n                type: string\n            forbiddenSysctls:\n              type: array\n              description: "A disallow-list of sysctls. `*` forbids all sysctls."\n              items:\n                type: string\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      rego: |\n        package k8spspforbiddensysctls\n\n        import data.lib.exclude_update.is_update\n\n        # Block if forbidden\n        violation[{"msg": msg, "details": {}}] {\n            # spec.securityContext.sysctls field is immutable.\n            not is_update(input.review)\n\n            sysctl := input.review.object.spec.securityContext.sysctls[_].name\n            forbidden_sysctl(sysctl)\n            msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.forbiddenSysctls])\n        }\n\n        # Block if not explicitly allowed\n        violation[{"msg": msg, "details": {}}] {\n            not is_update(input.review)\n            sysctl := input.review.object.spec.securityContext.sysctls[_].name\n            not allowed_sysctl(sysctl)\n            msg := sprintf("The sysctl %v is not explicitly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.allowedSysctls])\n        }\n\n        # * may be used to forbid all sysctls\n        forbidden_sysctl(_) {\n            input.parameters.forbiddenSysctls[_] == "*"\n        }\n\n        forbidden_sysctl(sysctl) {\n            input.parameters.forbiddenSysctls[_] == sysctl\n        }\n\n        forbidden_sysctl(sysctl) {\n            forbidden := input.parameters.forbiddenSysctls[_]\n            endswith(forbidden, "*")\n            startswith(sysctl, trim_suffix(forbidden, "*"))\n        }\n\n        # * may be used to allow all sysctls\n        allowed_sysctl(_) {\n            input.parameters.allowedSysctls[_] == "*"\n        }\n\n        allowed_sysctl(sysctl) {\n            input.parameters.allowedSysctls[_] == sysctl\n        }\n\n        allowed_sysctl(sysctl) {\n            allowed := input.parameters.allowedSysctls[_]\n            endswith(allowed, "*")\n            startswith(sysctl, trim_suffix(allowed, "*"))\n        }\n      libs:\n        - |\n          package lib.exclude_update\n\n          is_update(review) {\n              review.operation == "UPDATE"\n          }\n\n'})}),"\n",(0,t.jsx)(s.h3,{id:"usage",children:"Usage"}),"\n",(0,t.jsx)(s.pre,{children:(0,t.jsx)(s.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/template.yaml\n"})}),"\n",(0,t.jsx)(s.h2,{id:"examples",children:"Examples"}),"\n",(0,t.jsxs)(n,{children:[(0,t.jsx)("summary",{children:"forbidden-sysctls"}),(0,t.jsxs)(n,{children:[(0,t.jsx)("summary",{children:"constraint"}),(0,t.jsx)(s.pre,{children:(0,t.jsx)(s.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sPSPForbiddenSysctls\nmetadata:\n  name: psp-forbidden-sysctls\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    forbiddenSysctls:\n    # - "*" # * may be used to forbid all sysctls\n    - kernel.*\n    allowedSysctls:\n    - "*" # allows all sysctls. allowedSysctls is optional.\n\n'})}),(0,t.jsx)(s.p,{children:"Usage"}),(0,t.jsx)(s.pre,{children:(0,t.jsx)(s.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/samples/psp-forbidden-sysctls/constraint.yaml\n"})})]}),(0,t.jsxs)(n,{children:[(0,t.jsx)("summary",{children:"example-disallowed"}),(0,t.jsx)(s.pre,{children:(0,t.jsx)(s.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-forbidden-sysctls-disallowed\n  labels:\n    app: nginx-forbidden-sysctls\nspec:\n  containers:\n    - name: nginx\n      image: nginx\n  securityContext:\n    sysctls:\n      - name: kernel.msgmax\n        value: "65536"\n      - name: net.core.somaxconn\n        value: "1024"\n\n'})}),(0,t.jsx)(s.p,{children:"Usage"}),(0,t.jsx)(s.pre,{children:(0,t.jsx)(s.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/samples/psp-forbidden-sysctls/example_disallowed.yaml\n"})})]}),(0,t.jsxs)(n,{children:[(0,t.jsx)("summary",{children:"example-allowed"}),(0,t.jsx)(s.pre,{children:(0,t.jsx)(s.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-forbidden-sysctls-disallowed\n  labels:\n    app: nginx-forbidden-sysctls\nspec:\n  containers:\n    - name: nginx\n      image: nginx\n  securityContext:\n    sysctls:\n      - name: net.core.somaxconn\n        value: "1024"\n\n'})}),(0,t.jsx)(s.p,{children:"Usage"}),(0,t.jsx)(s.pre,{children:(0,t.jsx)(s.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/forbidden-sysctls/samples/psp-forbidden-sysctls/example_allowed.yaml\n"})})]})]})]})}function p(e={}){const{wrapper:s}={...(0,l.a)(),...e.components};return s?(0,t.jsx)(s,{...e,children:(0,t.jsx)(c,{...e})}):c(e)}},1151:(e,s,n)=>{n.d(s,{Z:()=>r,a:()=>a});var t=n(7294);const l={},i=t.createContext(l);function a(e){const s=t.useContext(i);return t.useMemo((function(){return"function"==typeof e?e(s):{...s,...e}}),[s,e])}function r(e){let s;return s=e.disableParentContext?"function"==typeof e.components?e.components(l):e.components||l:a(e.components),t.createElement(i.Provider,{value:s},e.children)}}}]);