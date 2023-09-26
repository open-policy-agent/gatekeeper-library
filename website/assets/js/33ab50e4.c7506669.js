"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[8164],{3905:(e,n,t)=>{t.d(n,{Zo:()=>u,kt:()=>d});var a=t(7294);function s(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function r(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);n&&(a=a.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,a)}return t}function i(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?r(Object(t),!0).forEach((function(n){s(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):r(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function l(e,n){if(null==e)return{};var t,a,s=function(e,n){if(null==e)return{};var t,a,s={},r=Object.keys(e);for(a=0;a<r.length;a++)t=r[a],n.indexOf(t)>=0||(s[t]=e[t]);return s}(e,n);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(a=0;a<r.length;a++)t=r[a],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(s[t]=e[t])}return s}var o=a.createContext({}),p=function(e){var n=a.useContext(o),t=n;return e&&(t="function"==typeof e?e(n):i(i({},n),e)),t},u=function(e){var n=p(e.components);return a.createElement(o.Provider,{value:n},e.children)},c="mdxType",m={inlineCode:"code",wrapper:function(e){var n=e.children;return a.createElement(a.Fragment,{},n)}},g=a.forwardRef((function(e,n){var t=e.components,s=e.mdxType,r=e.originalType,o=e.parentName,u=l(e,["components","mdxType","originalType","parentName"]),c=p(t),g=s,d=c["".concat(o,".").concat(g)]||c[g]||m[g]||r;return t?a.createElement(d,i(i({ref:n},u),{},{components:t})):a.createElement(d,i({ref:n},u))}));function d(e,n){var t=arguments,s=n&&n.mdxType;if("string"==typeof e||s){var r=t.length,i=new Array(r);i[0]=g;var l={};for(var o in n)hasOwnProperty.call(n,o)&&(l[o]=n[o]);l.originalType=e,l[c]="string"==typeof e?e:s,i[1]=l;for(var p=2;p<r;p++)i[p]=t[p];return a.createElement.apply(null,i)}return a.createElement.apply(null,t)}g.displayName="MDXCreateElement"},333:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>o,contentTitle:()=>i,default:()=>m,frontMatter:()=>r,metadata:()=>l,toc:()=>p});var a=t(7462),s=(t(7294),t(3905));const r={id:"uniqueingresshost",title:"Unique Ingress Host"},i="Unique Ingress Host",l={unversionedId:"validation/uniqueingresshost",id:"validation/uniqueingresshost",title:"Unique Ingress Host",description:"Description",source:"@site/docs/validation/uniqueingresshost.md",sourceDirName:"validation",slug:"/validation/uniqueingresshost",permalink:"/gatekeeper-library/website/validation/uniqueingresshost",draft:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/uniqueingresshost.md",tags:[],version:"current",frontMatter:{id:"uniqueingresshost",title:"Unique Ingress Host"},sidebar:"docs",previous:{title:"Storage Class",permalink:"/gatekeeper-library/website/validation/storageclass"},next:{title:"Unique Service Selector",permalink:"/gatekeeper-library/website/validation/uniqueserviceselector"}},o={},p=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}],u={toc:p},c="wrapper";function m(e){let{components:n,...t}=e;return(0,s.kt)(c,(0,a.Z)({},u,t,{components:n,mdxType:"MDXLayout"}),(0,s.kt)("h1",{id:"unique-ingress-host"},"Unique Ingress Host"),(0,s.kt)("h2",{id:"description"},"Description"),(0,s.kt)("p",null,"Requires all Ingress rule hosts to be unique.\nDoes not handle hostname wildcards: ",(0,s.kt)("a",{parentName:"p",href:"https://kubernetes.io/docs/concepts/services-networking/ingress/"},"https://kubernetes.io/docs/concepts/services-networking/ingress/")),(0,s.kt)("h2",{id:"template"},"Template"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8suniqueingresshost\n  annotations:\n    metadata.gatekeeper.sh/title: "Unique Ingress Host"\n    metadata.gatekeeper.sh/version: 1.0.3\n    metadata.gatekeeper.sh/requires-sync-data: |\n      "[\n        [\n          {\n            "groups": ["extensions"],\n            "versions": ["v1beta1"],\n            "kinds": ["Ingress"]\n          },\n          {\n            "groups": ["networking.k8s.io"],\n            "versions": ["v1beta1", "v1"],\n            "kinds": ["Ingress"]\n          }\n        ]\n      ]"\n    description: >-\n      Requires all Ingress rule hosts to be unique.\n\n      Does not handle hostname wildcards:\n      https://kubernetes.io/docs/concepts/services-networking/ingress/\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sUniqueIngressHost\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      rego: |\n        package k8suniqueingresshost\n\n        identical(obj, review) {\n          obj.metadata.namespace == review.object.metadata.namespace\n          obj.metadata.name == review.object.metadata.name\n        }\n\n        violation[{"msg": msg}] {\n          input.review.kind.kind == "Ingress"\n          re_match("^(extensions|networking.k8s.io)$", input.review.kind.group)\n          host := input.review.object.spec.rules[_].host\n          other := data.inventory.namespace[_][otherapiversion]["Ingress"][name]\n          re_match("^(extensions|networking.k8s.io)/.+$", otherapiversion)\n          other.spec.rules[_].host == host\n          not identical(other, input.review)\n          msg := sprintf("ingress host conflicts with an existing ingress <%v>", [host])\n        }\n\n')),(0,s.kt)("h3",{id:"usage"},"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueingresshost/template.yaml\n")),(0,s.kt)("h2",{id:"examples"},"Examples"),(0,s.kt)("details",null,(0,s.kt)("summary",null,"unique-ingress-host"),(0,s.kt)("blockquote",null,(0,s.kt)("details",null,(0,s.kt)("summary",null,"constraint"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sUniqueIngressHost\nmetadata:\n  name: unique-ingress-host\nspec:\n  match:\n    kinds:\n      - apiGroups: ["extensions", "networking.k8s.io"]\n        kinds: ["Ingress"]\n\n')),(0,s.kt)("p",null,"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueingresshost/samples/unique-ingress-host/constraint.yaml\n"))),(0,s.kt)("details",null,(0,s.kt)("summary",null,"example-allowed"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: ingress-host-allowed\n  namespace: default\nspec:\n  rules:\n  - host: example-allowed-host.example.com\n    http:\n      paths:\n      - pathType: Prefix\n        path: "/"\n        backend:\n          service:\n            name: nginx\n            port:\n              number: 80\n  - host: example-allowed-host1.example.com\n    http:\n      paths:\n      - pathType: Prefix\n        path: "/"\n        backend:\n          service:\n            name: nginx2\n            port:\n              number: 80\n\n')),(0,s.kt)("p",null,"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueingresshost/samples/unique-ingress-host/example_allowed.yaml\n"))),(0,s.kt)("details",null,(0,s.kt)("summary",null,"example-disallowed"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: ingress-host-disallowed\n  namespace: default\nspec:\n  rules:\n  - host: example-host.example.com\n    http:\n      paths:\n      - pathType: Prefix\n        path: "/"\n        backend:\n          service:\n            name: nginx\n            port:\n              number: 80\n\n')),(0,s.kt)("p",null,"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueingresshost/samples/unique-ingress-host/example_disallowed.yaml\n"))),(0,s.kt)("details",null,(0,s.kt)("summary",null,"example-disallowed2"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: ingress-host-disallowed2\n  namespace: default\nspec:\n  rules:\n  - host: example-host2.example.com\n    http:\n      paths:\n      - pathType: Prefix\n        path: "/"\n        backend:\n          service:\n            name: nginx\n            port:\n              number: 80\n  - host: example-host3.example.com\n    http:\n      paths:\n      - pathType: Prefix\n        path: "/"\n        backend:\n          service:\n            name: nginx2\n            port:\n              number: 80\n\n')),(0,s.kt)("p",null,"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueingresshost/samples/unique-ingress-host/example_disallowed2.yaml\n"))))))}m.isMDXComponent=!0}}]);