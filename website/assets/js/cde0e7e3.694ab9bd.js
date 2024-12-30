"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[3589],{8634:(e,n,s)=>{s.r(n),s.d(n,{assets:()=>l,contentTitle:()=>t,default:()=>c,frontMatter:()=>o,metadata:()=>i,toc:()=>p});var a=s(5893),r=s(1151);const o={id:"fsgroup",title:"FS Group"},t="FS Group",i={id:"validation/fsgroup",title:"FS Group",description:"Description",source:"@site/docs/validation/fsgroup.md",sourceDirName:"validation",slug:"/validation/fsgroup",permalink:"/gatekeeper-library/website/validation/fsgroup",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/fsgroup.md",tags:[],version:"current",frontMatter:{id:"fsgroup",title:"FS Group"},sidebar:"docs",previous:{title:"Forbidden Sysctls",permalink:"/gatekeeper-library/website/validation/forbidden-sysctls"},next:{title:"Host Filesystem",permalink:"/gatekeeper-library/website/validation/host-filesystem"}},l={},p=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function u(e){const n={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,r.a)(),...e.components},{Details:s}=n;return s||function(e,n){throw new Error("Expected "+(n?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,a.jsxs)(a.Fragment,{children:[(0,a.jsx)(n.h1,{id:"fs-group",children:"FS Group"}),"\n",(0,a.jsx)(n.h2,{id:"description",children:"Description"}),"\n",(0,a.jsxs)(n.p,{children:["Controls allocating an FSGroup that owns the Pod's volumes. Corresponds to the ",(0,a.jsx)(n.code,{children:"fsGroup"})," field in a PodSecurityPolicy. For more information, see ",(0,a.jsx)(n.a,{href:"https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems",children:"https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems"})]}),"\n",(0,a.jsx)(n.h2,{id:"template",children:"Template"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8spspfsgroup\n  annotations:\n    metadata.gatekeeper.sh/title: "FS Group"\n    metadata.gatekeeper.sh/version: 1.1.0\n    description: >-\n      Controls allocating an FSGroup that owns the Pod\'s volumes. Corresponds\n      to the `fsGroup` field in a PodSecurityPolicy. For more information, see\n      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sPSPFSGroup\n      validation:\n        # Schema for the `parameters` field\n        openAPIV3Schema:\n          type: object\n          description: >-\n            Controls allocating an FSGroup that owns the Pod\'s volumes. Corresponds\n            to the `fsGroup` field in a PodSecurityPolicy. For more information, see\n            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems\n          properties:\n            rule:\n              description: "An FSGroup rule name."\n              enum:\n                - MayRunAs\n                - MustRunAs\n                - RunAsAny\n              type: string\n            ranges:\n              type: array\n              description: "GID ranges affected by the rule."\n              items:\n                type: object\n                properties:\n                  min:\n                    description: "The minimum GID in the range, inclusive."\n                    type: integer\n                  max:\n                    description: "The maximum GID in the range, inclusive."\n                    type: integer\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      code:\n      - engine: K8sNativeValidation\n        source:\n          variables:\n          - name: isUpdate\n            expression: has(request.operation) && request.operation == "UPDATE"\n          - name: fsGroup\n            expression: \'!has(variables.anyObject.spec.securityContext) ? "" : !has(variables.anyObject.spec.securityContext.fsGroup) ? "" : variables.anyObject.spec.securityContext.fsGroup\'\n          - name: ruleString\n            expression: |\n              !has(variables.params.rule) ? "unspecified" : string(variables.params.rule)\n          - name: rangesString\n            expression: |\n              !has(variables.params.ranges) ? "unspecified" : size(variables.params.ranges) == 0 ? "empty" : variables.params.ranges.map(r, string(r)).join(", ")\n          - name: input_fsGroup_allowed\n            expression: |\n              !has(variables.params.rule) ? true : variables.params.rule == "RunAsAny" ? true : variables.params.rule == "MayRunAs" && variables.fsGroup == "" ? true : (variables.params.rule == "MayRunAs" || variables.params.rule == "MustRunAs") && has(variables.params.ranges) && size(variables.params.ranges) > 0 ? variables.params.ranges.exists(range, range.min <= variables.fsGroup && range.max >= variables.fsGroup) : false\n          validations:\n          - expression: \'variables.isUpdate || variables.input_fsGroup_allowed\'\n            messageExpression: \'"The provided pod spec fsGroup is not allowed, pod: " + variables.anyObject.metadata.name + ". Allowed fsGroup rule: " + variables.ruleString + ", allowed fsGroup ranges: " + variables.rangesString\'\n      - engine: Rego\n        source:\n          rego: |\n            package k8spspfsgroup\n\n            import data.lib.exclude_update.is_update\n\n            violation[{"msg": msg, "details": {}}] {\n                # spec.securityContext.fsGroup field is immutable.\n                not is_update(input.review)\n                has_field(input.parameters, "rule")\n                spec := input.review.object.spec\n                not input_fsGroup_allowed(spec)\n                msg := sprintf("The provided pod spec fsGroup is not allowed, pod: %v. Allowed fsGroup: %v", [input.review.object.metadata.name, input.parameters])\n            }\n\n            input_fsGroup_allowed(_) {\n                # RunAsAny - No range is required. Allows any fsGroup ID to be specified.\n                input.parameters.rule == "RunAsAny"\n            }\n            input_fsGroup_allowed(spec) {\n                # MustRunAs - Validates pod spec fsgroup against all ranges\n                input.parameters.rule == "MustRunAs"\n                fg := spec.securityContext.fsGroup\n                count(input.parameters.ranges) > 0\n                range := input.parameters.ranges[_]\n                value_within_range(range, fg)\n            }\n            input_fsGroup_allowed(spec) {\n                # MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset\n                input.parameters.rule == "MayRunAs"\n                not has_field(spec, "securityContext")\n            }\n            input_fsGroup_allowed(spec) {\n                # MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset\n                input.parameters.rule == "MayRunAs"\n                not spec.securityContext.fsGroup\n            }\n            input_fsGroup_allowed(spec) {\n                # MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset\n                input.parameters.rule == "MayRunAs"\n                fg := spec.securityContext.fsGroup\n                count(input.parameters.ranges) > 0\n                range := input.parameters.ranges[_]\n                value_within_range(range, fg)\n            }\n            value_within_range(range, value) {\n                range.min <= value\n                range.max >= value\n            }\n            # has_field returns whether an object has a field\n            has_field(object, field) = true {\n                object[field]\n            }\n          libs:\n            - |\n              package lib.exclude_update\n\n              is_update(review) {\n                  review.operation == "UPDATE"\n              }\n\n'})}),"\n",(0,a.jsx)(n.h3,{id:"usage",children:"Usage"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/fsgroup/template.yaml\n"})}),"\n",(0,a.jsx)(n.h2,{id:"examples",children:"Examples"}),"\n",(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"fsgroup"}),(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"constraint"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sPSPFSGroup\nmetadata:\n  name: psp-fsgroup\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    rule: "MayRunAs" #"MustRunAs" #"MayRunAs", "RunAsAny"\n    ranges:\n    - min: 1\n      max: 1000\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/fsgroup/samples/psp-fsgroup/constraint.yaml\n"})})]}),(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"example-disallowed"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: fsgroup-disallowed\nspec:\n  securityContext:\n    fsGroup: 2000                           # directory will have group ID 2000\n  volumes:\n  - name: fsgroup-demo-vol\n    emptyDir: {}\n  containers:\n  - name: fsgroup-demo\n    image: busybox\n    command: [ "sh", "-c", "sleep 1h" ]\n    volumeMounts:\n    - name: fsgroup-demo-vol\n      mountPath: /data/demo\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/fsgroup/samples/psp-fsgroup/example_disallowed.yaml\n"})})]}),(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"example-allowed"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: fsgroup-allowed\nspec:\n  securityContext:\n    fsGroup: 500 # directory will have group ID 500\n  volumes:\n    - name: fsgroup-demo-vol\n      emptyDir: {}\n  containers:\n    - name: fsgroup-demo\n      image: busybox\n      command: ["sh", "-c", "sleep 1h"]\n      volumeMounts:\n        - name: fsgroup-demo-vol\n          mountPath: /data/demo\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/fsgroup/samples/psp-fsgroup/example_allowed.yaml\n"})})]})]}),"\n",(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"fsgroup-no-rules"}),(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"constraint"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sPSPFSGroup\nmetadata:\n  name: psp-fsgroup\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    ranges:\n    - min: 1\n      max: 1000\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/fsgroup/samples/psp-fsgroup/constraint2.yaml\n"})})]}),(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"example-allowed"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: fsgroup-disallowed\nspec:\n  securityContext:\n    fsGroup: 2000                           # directory will have group ID 2000\n  volumes:\n  - name: fsgroup-demo-vol\n    emptyDir: {}\n  containers:\n  - name: fsgroup-demo\n    image: busybox\n    command: [ "sh", "-c", "sleep 1h" ]\n    volumeMounts:\n    - name: fsgroup-demo-vol\n      mountPath: /data/demo\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/fsgroup/samples/psp-fsgroup/example_disallowed.yaml\n"})})]}),(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"example-allowed"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: fsgroup-allowed\nspec:\n  securityContext:\n    fsGroup: 500 # directory will have group ID 500\n  volumes:\n    - name: fsgroup-demo-vol\n      emptyDir: {}\n  containers:\n    - name: fsgroup-demo\n      image: busybox\n      command: ["sh", "-c", "sleep 1h"]\n      volumeMounts:\n        - name: fsgroup-demo-vol\n          mountPath: /data/demo\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/fsgroup/samples/psp-fsgroup/example_allowed.yaml\n"})})]})]}),"\n",(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"fsgroup-empty-ranges"}),(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"constraint"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sPSPFSGroup\nmetadata:\n  name: psp-fsgroup\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    rule: "MustRunAs" #"MayRunAs", "RunAsAny"\n    ranges: [] # empty ranges should result in violation\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/fsgroup/samples/psp-fsgroup/constraint3.yaml\n"})})]}),(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"example-disallowed-2000"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: fsgroup-disallowed\nspec:\n  securityContext:\n    fsGroup: 2000                           # directory will have group ID 2000\n  volumes:\n  - name: fsgroup-demo-vol\n    emptyDir: {}\n  containers:\n  - name: fsgroup-demo\n    image: busybox\n    command: [ "sh", "-c", "sleep 1h" ]\n    volumeMounts:\n    - name: fsgroup-demo-vol\n      mountPath: /data/demo\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/fsgroup/samples/psp-fsgroup/example_disallowed.yaml\n"})})]}),(0,a.jsxs)(s,{children:[(0,a.jsx)("summary",{children:"example-disallowed-500"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: v1\nkind: Pod\nmetadata:\n  name: fsgroup-allowed\nspec:\n  securityContext:\n    fsGroup: 500 # directory will have group ID 500\n  volumes:\n    - name: fsgroup-demo-vol\n      emptyDir: {}\n  containers:\n    - name: fsgroup-demo\n      image: busybox\n      command: ["sh", "-c", "sleep 1h"]\n      volumeMounts:\n        - name: fsgroup-demo-vol\n          mountPath: /data/demo\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/fsgroup/samples/psp-fsgroup/example_allowed.yaml\n"})})]})]})]})}function c(e={}){const{wrapper:n}={...(0,r.a)(),...e.components};return n?(0,a.jsx)(n,{...e,children:(0,a.jsx)(u,{...e})}):u(e)}},1151:(e,n,s)=>{s.d(n,{Z:()=>i,a:()=>t});var a=s(7294);const r={},o=a.createContext(r);function t(e){const n=a.useContext(o);return a.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function i(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(r):e.components||r:t(e.components),a.createElement(o.Provider,{value:n},e.children)}}}]);