"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[4381],{8814:(e,a,n)=>{n.r(a),n.d(a,{assets:()=>i,contentTitle:()=>t,default:()=>p,frontMatter:()=>s,metadata:()=>c,toc:()=>o});var l=n(5893),r=n(1151);const s={id:"block-loadbalancer-services",title:"Block Services with type LoadBalancer"},t="Block Services with type LoadBalancer",c={id:"validation/block-loadbalancer-services",title:"Block Services with type LoadBalancer",description:"Description",source:"@site/docs/validation/block-loadbalancer-services.md",sourceDirName:"validation",slug:"/validation/block-loadbalancer-services",permalink:"/gatekeeper-library/website/validation/block-loadbalancer-services",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/block-loadbalancer-services.md",tags:[],version:"current",frontMatter:{id:"block-loadbalancer-services",title:"Block Services with type LoadBalancer"},sidebar:"docs",previous:{title:"Block Endpoint Edit Default Role",permalink:"/gatekeeper-library/website/validation/block-endpoint-edit-default-role"},next:{title:"Block NodePort",permalink:"/gatekeeper-library/website/validation/block-nodeport-services"}},i={},o=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function d(e){const a={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,r.a)(),...e.components},{Details:n}=a;return n||function(e,a){throw new Error("Expected "+(a?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,l.jsxs)(l.Fragment,{children:[(0,l.jsx)(a.h1,{id:"block-services-with-type-loadbalancer",children:"Block Services with type LoadBalancer"}),"\n",(0,l.jsx)(a.h2,{id:"description",children:"Description"}),"\n",(0,l.jsxs)(a.p,{children:["Disallows all Services with type LoadBalancer.\n",(0,l.jsx)(a.a,{href:"https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer",children:"https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer"})]}),"\n",(0,l.jsx)(a.h2,{id:"template",children:"Template"}),"\n",(0,l.jsx)(a.pre,{children:(0,l.jsx)(a.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8sblockloadbalancer\n  annotations:\n    metadata.gatekeeper.sh/title: "Block Services with type LoadBalancer"\n    metadata.gatekeeper.sh/version: 1.0.0\n    description: >-\n      Disallows all Services with type LoadBalancer.\n\n      https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sBlockLoadBalancer\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      rego: |\n        package k8sblockloadbalancer\n\n        violation[{"msg": msg}] {\n          input.review.kind.kind == "Service"\n          input.review.object.spec.type == "LoadBalancer"\n          msg := "User is not allowed to create service of type LoadBalancer"\n        }\n\n'})}),"\n",(0,l.jsx)(a.h3,{id:"usage",children:"Usage"}),"\n",(0,l.jsx)(a.pre,{children:(0,l.jsx)(a.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-loadbalancer-services/template.yaml\n"})}),"\n",(0,l.jsx)(a.h2,{id:"examples",children:"Examples"}),"\n",(0,l.jsxs)(n,{children:[(0,l.jsx)("summary",{children:"block-loadbalancer-services"}),(0,l.jsxs)(n,{children:[(0,l.jsx)("summary",{children:"constraint"}),(0,l.jsx)(a.pre,{children:(0,l.jsx)(a.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sBlockLoadBalancer\nmetadata:\n  name: block-load-balancer\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Service"]\n\n'})}),(0,l.jsx)(a.p,{children:"Usage"}),(0,l.jsx)(a.pre,{children:(0,l.jsx)(a.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-loadbalancer-services/samples/block-load-balancer/constraint.yaml\n"})})]}),(0,l.jsxs)(n,{children:[(0,l.jsx)("summary",{children:"example-allowed"}),(0,l.jsx)(a.pre,{children:(0,l.jsx)(a.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Service\nmetadata:\n  name: my-service-allowed\nspec:\n  type: ClusterIP\n  ports:\n    - port: 80\n      targetPort: 80\n\n"})}),(0,l.jsx)(a.p,{children:"Usage"}),(0,l.jsx)(a.pre,{children:(0,l.jsx)(a.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-loadbalancer-services/samples/block-load-balancer/example_allowed.yaml\n"})})]}),(0,l.jsxs)(n,{children:[(0,l.jsx)("summary",{children:"example-disallowed"}),(0,l.jsx)(a.pre,{children:(0,l.jsx)(a.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Service\nmetadata:\n  name: my-service-disallowed\nspec:\n  type: LoadBalancer\n  ports:\n    - port: 80\n      targetPort: 80\n      nodePort: 30007\n\n"})}),(0,l.jsx)(a.p,{children:"Usage"}),(0,l.jsx)(a.pre,{children:(0,l.jsx)(a.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-loadbalancer-services/samples/block-load-balancer/example_disallowed.yaml\n"})})]})]})]})}function p(e={}){const{wrapper:a}={...(0,r.a)(),...e.components};return a?(0,l.jsx)(a,{...e,children:(0,l.jsx)(d,{...e})}):d(e)}},1151:(e,a,n)=>{n.d(a,{Z:()=>c,a:()=>t});var l=n(7294);const r={},s=l.createContext(r);function t(e){const a=l.useContext(s);return l.useMemo((function(){return"function"==typeof e?e(a):{...a,...e}}),[a,e])}function c(e){let a;return a=e.disableParentContext?"function"==typeof e.components?e.components(r):e.components||r:t(e.components),l.createElement(s.Provider,{value:a},e.children)}}}]);