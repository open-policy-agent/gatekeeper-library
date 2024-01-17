"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[6626],{9107:(e,n,i)=>{i.r(n),i.d(n,{assets:()=>l,contentTitle:()=>a,default:()=>p,frontMatter:()=>r,metadata:()=>c,toc:()=>o});var s=i(5893),t=i(1151);const r={id:"uniqueserviceselector",title:"Unique Service Selector"},a="Unique Service Selector",c={id:"validation/uniqueserviceselector",title:"Unique Service Selector",description:"Description",source:"@site/docs/validation/uniqueserviceselector.md",sourceDirName:"validation",slug:"/validation/uniqueserviceselector",permalink:"/gatekeeper-library/website/validation/uniqueserviceselector",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/uniqueserviceselector.md",tags:[],version:"current",frontMatter:{id:"uniqueserviceselector",title:"Unique Service Selector"},sidebar:"docs",previous:{title:"Unique Ingress Host",permalink:"/gatekeeper-library/website/validation/uniqueingresshost"},next:{title:"Verify deprecated APIs",permalink:"/gatekeeper-library/website/validation/verifydeprecatedapi"}},l={},o=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function d(e){const n={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,t.a)(),...e.components},{Details:i}=n;return i||function(e,n){throw new Error("Expected "+(n?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(n.h1,{id:"unique-service-selector",children:"Unique Service Selector"}),"\n",(0,s.jsx)(n.h2,{id:"description",children:"Description"}),"\n",(0,s.jsxs)(n.p,{children:["Requires Services to have unique selectors within a namespace. Selectors are considered the same if they have identical keys and values. Selectors may share a key/value pair so long as there is at least one distinct key/value pair between them.\n",(0,s.jsx)(n.a,{href:"https://kubernetes.io/docs/concepts/services-networking/service/#defining-a-service",children:"https://kubernetes.io/docs/concepts/services-networking/service/#defining-a-service"})]}),"\n",(0,s.jsx)(n.h2,{id:"template",children:"Template"}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8suniqueserviceselector\n  annotations:\n    metadata.gatekeeper.sh/title: "Unique Service Selector"\n    metadata.gatekeeper.sh/version: 1.0.2\n    metadata.gatekeeper.sh/requires-sync-data: |\n      "[\n        [\n          {\n            "groups":[""],\n            "versions": ["v1"],\n            "kinds": ["Service"]\n          }\n        ]\n      ]"\n    description: >-\n      Requires Services to have unique selectors within a namespace.\n      Selectors are considered the same if they have identical keys and values.\n      Selectors may share a key/value pair so long as there is at least one\n      distinct key/value pair between them.\n\n      https://kubernetes.io/docs/concepts/services-networking/service/#defining-a-service\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sUniqueServiceSelector\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      rego: |\n        package k8suniqueserviceselector\n\n        make_apiversion(kind) = apiVersion {\n          g := kind.group\n          v := kind.version\n          g != ""\n          apiVersion = sprintf("%v/%v", [g, v])\n        }\n\n        make_apiversion(kind) = apiVersion {\n          kind.group == ""\n          apiVersion = kind.version\n        }\n\n        identical(obj, review) {\n          obj.metadata.namespace == review.namespace\n          obj.metadata.name == review.name\n          obj.kind == review.kind.kind\n          obj.apiVersion == make_apiversion(review.kind)\n        }\n\n        flatten_selector(obj) = flattened {\n          selectors := [s | s = concat(":", [key, val]); val = obj.spec.selector[key]]\n          flattened := concat(",", sort(selectors))\n        }\n\n        violation[{"msg": msg}] {\n          input.review.kind.kind == "Service"\n          input.review.kind.version == "v1"\n          input.review.kind.group == ""\n          input_selector := flatten_selector(input.review.object)\n          other := data.inventory.namespace[namespace][_]["Service"][name]\n          not identical(other, input.review)\n          other_selector := flatten_selector(other)\n          input_selector == other_selector\n          msg := sprintf("same selector as service <%v> in namespace <%v>", [name, namespace])\n        }\n\n'})}),"\n",(0,s.jsx)(n.h3,{id:"usage",children:"Usage"}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueserviceselector/template.yaml\n"})}),"\n",(0,s.jsx)(n.h2,{id:"examples",children:"Examples"}),"\n",(0,s.jsxs)(i,{children:[(0,s.jsx)("summary",{children:"unique-service-selector"}),(0,s.jsxs)(i,{children:[(0,s.jsx)("summary",{children:"constraint"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sUniqueServiceSelector\nmetadata:\n  name: unique-service-selector\n  labels:\n    owner: admin.agilebank.demo\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueserviceselector/samples/unique-service-selector/constraint.yaml\n"})})]}),(0,s.jsxs)(i,{children:[(0,s.jsx)("summary",{children:"example-allowed"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Service\nmetadata:\n  name: gatekeeper-test-service-disallowed\n  namespace: default\nspec:\n  ports:\n    - port: 443\n  selector:\n    key: other-value\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueserviceselector/samples/unique-service-selector/example_allowed.yaml\n"})})]}),(0,s.jsxs)(i,{children:[(0,s.jsx)("summary",{children:"example-disallowed"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Service\nmetadata:\n  name: gatekeeper-test-service-disallowed\n  namespace: default\nspec:\n  ports:\n    - port: 443\n  selector:\n    key: value\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueserviceselector/samples/unique-service-selector/example_disallowed.yaml\n"})})]})]})]})}function p(e={}){const{wrapper:n}={...(0,t.a)(),...e.components};return n?(0,s.jsx)(n,{...e,children:(0,s.jsx)(d,{...e})}):d(e)}},1151:(e,n,i)=>{i.d(n,{Z:()=>c,a:()=>a});var s=i(7294);const t={},r=s.createContext(t);function a(e){const n=s.useContext(r);return s.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function c(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(t):e.components||t:a(e.components),s.createElement(r.Provider,{value:n},e.children)}}}]);