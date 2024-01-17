"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[8090],{8268:(e,n,i)=>{i.r(n),i.d(n,{assets:()=>p,contentTitle:()=>l,default:()=>m,frontMatter:()=>s,metadata:()=>r,toc:()=>c});var a=i(5893),t=i(1151);const s={id:"replicalimits",title:"Replica Limits"},l="Replica Limits",r={id:"validation/replicalimits",title:"Replica Limits",description:"Description",source:"@site/docs/validation/replicalimits.md",sourceDirName:"validation",slug:"/validation/replicalimits",permalink:"/gatekeeper-library/website/validation/replicalimits",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/replicalimits.md",tags:[],version:"current",frontMatter:{id:"replicalimits",title:"Replica Limits"},sidebar:"docs",previous:{title:"Pod Disruption Budget",permalink:"/gatekeeper-library/website/validation/poddisruptionbudget"},next:{title:"Required Annotations",permalink:"/gatekeeper-library/website/validation/requiredannotations"}},p={},c=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function o(e){const n={code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,t.a)(),...e.components},{Details:i}=n;return i||function(e,n){throw new Error("Expected "+(n?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,a.jsxs)(a.Fragment,{children:[(0,a.jsx)(n.h1,{id:"replica-limits",children:"Replica Limits"}),"\n",(0,a.jsx)(n.h2,{id:"description",children:"Description"}),"\n",(0,a.jsxs)(n.p,{children:["Requires that objects with the field ",(0,a.jsx)(n.code,{children:"spec.replicas"})," (Deployments, ReplicaSets, etc.) specify a number of replicas within defined ranges."]}),"\n",(0,a.jsx)(n.h2,{id:"template",children:"Template"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8sreplicalimits\n  annotations:\n    metadata.gatekeeper.sh/title: "Replica Limits"\n    metadata.gatekeeper.sh/version: 1.0.2\n    description: >-\n      Requires that objects with the field `spec.replicas` (Deployments,\n      ReplicaSets, etc.) specify a number of replicas within defined ranges.\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sReplicaLimits\n      validation:\n        # Schema for the `parameters` field\n        openAPIV3Schema:\n          type: object\n          properties:\n            ranges:\n              type: array\n              description: Allowed ranges for numbers of replicas.  Values are inclusive.\n              items:\n                type: object\n                description: A range of allowed replicas.  Values are inclusive.\n                properties:\n                  min_replicas:\n                    description: The minimum number of replicas allowed, inclusive.\n                    type: integer\n                  max_replicas:\n                    description: The maximum number of replicas allowed, inclusive.\n                    type: integer\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      rego: |\n        package k8sreplicalimits\n\n        object_name = input.review.object.metadata.name\n        object_kind = input.review.kind.kind\n\n        violation[{"msg": msg}] {\n            spec := input.review.object.spec\n            not input_replica_limit(spec)\n            msg := sprintf("The provided number of replicas is not allowed for %v: %v. Allowed ranges: %v", [object_kind, object_name, input.parameters])\n        }\n\n        input_replica_limit(spec) {\n            provided := spec.replicas\n            count(input.parameters.ranges) > 0\n            range := input.parameters.ranges[_]\n            value_within_range(range, provided)\n        }\n\n        value_within_range(range, value) {\n            range.min_replicas <= value\n            range.max_replicas >= value\n        }\n\n'})}),"\n",(0,a.jsx)(n.h3,{id:"usage",children:"Usage"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/replicalimits/template.yaml\n"})}),"\n",(0,a.jsx)(n.h2,{id:"examples",children:"Examples"}),"\n",(0,a.jsxs)(i,{children:[(0,a.jsx)("summary",{children:"replica-limit"}),(0,a.jsxs)(i,{children:[(0,a.jsx)("summary",{children:"constraint"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sReplicaLimits\nmetadata:\n  name: replica-limits\nspec:\n  match:\n    kinds:\n      - apiGroups: ["apps"]\n        kinds: ["Deployment"]\n  parameters:\n    ranges:\n    - min_replicas: 3\n      max_replicas: 50\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/replicalimits/samples/replicalimits/constraint.yaml\n"})})]}),(0,a.jsxs)(i,{children:[(0,a.jsx)("summary",{children:"example-allowed"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: allowed-deployment\nspec:\n  selector:\n    matchLabels:\n      app: nginx\n  replicas: 3\n  template:\n    metadata:\n      labels:\n        app: nginx\n    spec:\n      containers:\n      - name: nginx\n        image: nginx:1.14.2\n        ports:\n        - containerPort: 80\n\n"})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/replicalimits/samples/replicalimits/example_allowed.yaml\n"})})]}),(0,a.jsxs)(i,{children:[(0,a.jsx)("summary",{children:"example-disallowed"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: disallowed-deployment\nspec:\n  selector:\n    matchLabels:\n      app: nginx\n  replicas: 100\n  template:\n    metadata:\n      labels:\n        app: nginx\n    spec:\n      containers:\n      - name: nginx\n        image: nginx:1.14.2\n        ports:\n        - containerPort: 80\n\n"})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/replicalimits/samples/replicalimits/example_disallowed.yaml\n"})})]})]})]})}function m(e={}){const{wrapper:n}={...(0,t.a)(),...e.components};return n?(0,a.jsx)(n,{...e,children:(0,a.jsx)(o,{...e})}):o(e)}},1151:(e,n,i)=>{i.d(n,{Z:()=>r,a:()=>l});var a=i(7294);const t={},s=a.createContext(t);function l(e){const n=a.useContext(s);return a.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function r(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(t):e.components||t:l(e.components),a.createElement(s.Provider,{value:n},e.children)}}}]);