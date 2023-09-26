"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[1880],{3905:(e,t,n)=>{n.d(t,{Zo:()=>c,kt:()=>d});var a=n(7294);function s(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function r(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function l(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?r(Object(n),!0).forEach((function(t){s(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):r(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function o(e,t){if(null==e)return{};var n,a,s=function(e,t){if(null==e)return{};var n,a,s={},r=Object.keys(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||(s[n]=e[n]);return s}(e,t);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(s[n]=e[n])}return s}var i=a.createContext({}),p=function(e){var t=a.useContext(i),n=t;return e&&(n="function"==typeof e?e(t):l(l({},t),e)),n},c=function(e){var t=p(e.components);return a.createElement(i.Provider,{value:t},e.children)},m="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},g=a.forwardRef((function(e,t){var n=e.components,s=e.mdxType,r=e.originalType,i=e.parentName,c=o(e,["components","mdxType","originalType","parentName"]),m=p(n),g=s,d=m["".concat(i,".").concat(g)]||m[g]||u[g]||r;return n?a.createElement(d,l(l({ref:t},c),{},{components:n})):a.createElement(d,l({ref:t},c))}));function d(e,t){var n=arguments,s=t&&t.mdxType;if("string"==typeof e||s){var r=n.length,l=new Array(r);l[0]=g;var o={};for(var i in t)hasOwnProperty.call(t,i)&&(o[i]=t[i]);o.originalType=e,o[m]="string"==typeof e?e:s,l[1]=o;for(var p=2;p<r;p++)l[p]=n[p];return a.createElement.apply(null,l)}return a.createElement.apply(null,n)}g.displayName="MDXCreateElement"},3484:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>i,contentTitle:()=>l,default:()=>u,frontMatter:()=>r,metadata:()=>o,toc:()=>p});var a=n(7462),s=(n(7294),n(3905));const r={id:"httpsonly",title:"HTTPS Only"},l="HTTPS Only",o={unversionedId:"validation/httpsonly",id:"validation/httpsonly",title:"HTTPS Only",description:"Description",source:"@site/docs/validation/httpsonly.md",sourceDirName:"validation",slug:"/validation/httpsonly",permalink:"/gatekeeper-library/website/validation/httpsonly",draft:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/httpsonly.md",tags:[],version:"current",frontMatter:{id:"httpsonly",title:"HTTPS Only"},sidebar:"docs",previous:{title:"Horizontal Pod Autoscaler",permalink:"/gatekeeper-library/website/validation/horizontalpodautoscaler"},next:{title:"Image Digests",permalink:"/gatekeeper-library/website/validation/imagedigests"}},i={},p=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}],c={toc:p},m="wrapper";function u(e){let{components:t,...n}=e;return(0,s.kt)(m,(0,a.Z)({},c,n,{components:t,mdxType:"MDXLayout"}),(0,s.kt)("h1",{id:"https-only"},"HTTPS Only"),(0,s.kt)("h2",{id:"description"},"Description"),(0,s.kt)("p",null,"Requires Ingress resources to be HTTPS only.  Ingress resources must include the ",(0,s.kt)("inlineCode",{parentName:"p"},"kubernetes.io/ingress.allow-http")," annotation, set to ",(0,s.kt)("inlineCode",{parentName:"p"},"false"),". By default a valid TLS {} configuration is required, this can be made optional by setting the ",(0,s.kt)("inlineCode",{parentName:"p"},"tlsOptional")," parameter to ",(0,s.kt)("inlineCode",{parentName:"p"},"true"),".\n",(0,s.kt)("a",{parentName:"p",href:"https://kubernetes.io/docs/concepts/services-networking/ingress/#tls"},"https://kubernetes.io/docs/concepts/services-networking/ingress/#tls")),(0,s.kt)("h2",{id:"template"},"Template"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8shttpsonly\n  annotations:\n    metadata.gatekeeper.sh/title: "HTTPS Only"\n    metadata.gatekeeper.sh/version: 1.0.1\n    description: >-\n      Requires Ingress resources to be HTTPS only.  Ingress resources must\n      include the `kubernetes.io/ingress.allow-http` annotation, set to `false`.\n      By default a valid TLS {} configuration is required, this can be made\n      optional by setting the `tlsOptional` parameter to `true`.\n\n      https://kubernetes.io/docs/concepts/services-networking/ingress/#tls\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sHttpsOnly\n      validation:\n        # Schema for the `parameters` field\n        openAPIV3Schema:\n          type: object\n          description: >-\n            Requires Ingress resources to be HTTPS only.  Ingress resources must\n            include the `kubernetes.io/ingress.allow-http` annotation, set to\n            `false`. By default a valid TLS {} configuration is required, this\n            can be made optional by setting the `tlsOptional` parameter to\n            `true`.\n          properties:\n            tlsOptional:\n              type: boolean\n              description: "When set to `true` the TLS {} is optional, defaults\n              to false."\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      rego: |\n        package k8shttpsonly\n\n        violation[{"msg": msg}] {\n          input.review.object.kind == "Ingress"\n          re_match("^(extensions|networking.k8s.io)/", input.review.object.apiVersion)\n          ingress := input.review.object\n          not https_complete(ingress)\n          not tls_is_optional(ingress)\n          msg := sprintf("Ingress should be https. tls configuration and allow-http=false annotation are required for %v", [ingress.metadata.name])\n        }\n\n        violation[{"msg": msg}] {\n          input.review.object.kind == "Ingress"\n          re_match("^(extensions|networking.k8s.io)/", input.review.object.apiVersion)\n          ingress := input.review.object\n          not annotation_complete(ingress)\n          not tls_not_optional(ingress)\n          msg := sprintf("Ingress should be https. The allow-http=false annotation is required for %v", [ingress.metadata.name])\n        }\n\n        https_complete(ingress) = true {\n          ingress.spec["tls"]\n          count(ingress.spec.tls) > 0\n          ingress.metadata.annotations["kubernetes.io/ingress.allow-http"] == "false"\n        }\n\n        annotation_complete(ingress) = true {\n          ingress.metadata.annotations["kubernetes.io/ingress.allow-http"] == "false"\n        }\n\n        tls_is_optional(ingress) = true {\n          parameters := object.get(input, "parameters", {})\n          tlsOptional := object.get(parameters, "tlsOptional", false)\n          is_boolean(tlsOptional)\n          true == tlsOptional\n        }\n\n        tls_not_optional(ingress) = true {\n          parameters := object.get(input, "parameters", {})\n          tlsOptional := object.get(parameters, "tlsOptional", false)\n          true != tlsOptional\n        }\n\n')),(0,s.kt)("h3",{id:"usage"},"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/template.yaml\n")),(0,s.kt)("h2",{id:"examples"},"Examples"),(0,s.kt)("details",null,(0,s.kt)("summary",null,"tls-required"),(0,s.kt)("blockquote",null,(0,s.kt)("details",null,(0,s.kt)("summary",null,"constraint"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sHttpsOnly\nmetadata:\n  name: ingress-https-only\nspec:\n  match:\n    kinds:\n      - apiGroups: ["extensions", "networking.k8s.io"]\n        kinds: ["Ingress"]\n\n')),(0,s.kt)("p",null,"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only/constraint.yaml\n"))),(0,s.kt)("details",null,(0,s.kt)("summary",null,"example-allowed"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: ingress-demo-allowed\n  annotations:\n    kubernetes.io/ingress.allow-http: "false"\nspec:\n  tls: [{}]\n  rules:\n    - host: example-host.example.com\n      http:\n        paths:\n        - pathType: Prefix\n          path: "/"\n          backend:\n            service:\n              name: nginx\n              port:\n                number: 80\n\n')),(0,s.kt)("p",null,"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only/example_allowed.yaml\n"))),(0,s.kt)("details",null,(0,s.kt)("summary",null,"example-disallowed"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: ingress-demo-disallowed\nspec:\n  rules:\n    - host: example-host.example.com\n      http:\n        paths:\n        - pathType: Prefix\n          path: "/"\n          backend:\n            service:\n              name: nginx\n              port:\n                number: 80\n\n')),(0,s.kt)("p",null,"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only/example_disallowed.yaml\n"))))),(0,s.kt)("details",null,(0,s.kt)("summary",null,"tls-optional"),(0,s.kt)("blockquote",null,(0,s.kt)("details",null,(0,s.kt)("summary",null,"constraint"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sHttpsOnly\nmetadata:\n  name: ingress-https-only-tls-optional\nspec:\n  match:\n    kinds:\n      - apiGroups: ["extensions", "networking.k8s.io"]\n        kinds: ["Ingress"]\n  parameters:\n    tlsOptional: true\n\n')),(0,s.kt)("p",null,"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only-tls-optional/constraint.yaml\n"))),(0,s.kt)("details",null,(0,s.kt)("summary",null,"example-allowed-tls-optional"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: ingress-demo-allowed-tls-optional\n  annotations:\n    kubernetes.io/ingress.allow-http: "false"\nspec:\n  rules:\n    - host: example-host.example.com\n      http:\n        paths:\n        - pathType: Prefix\n          path: "/"\n          backend:\n            service:\n              name: nginx\n              port:\n                number: 80\n\n')),(0,s.kt)("p",null,"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only-tls-optional/example_allowed.yaml\n"))),(0,s.kt)("details",null,(0,s.kt)("summary",null,"example-disallowed-tls-optional"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: ingress-demo-disallowed-tls-optional\nspec:\n  rules:\n    - host: example-host.example.com\n      http:\n        paths:\n        - pathType: Prefix\n          path: "/"\n          backend:\n            service:\n              name: nginx\n              port:\n                number: 80\n\n')),(0,s.kt)("p",null,"Usage"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-shell"},"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only-tls-optional/example_disallowed.yaml\n"))))))}u.isMDXComponent=!0}}]);