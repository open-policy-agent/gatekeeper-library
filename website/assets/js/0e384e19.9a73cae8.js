"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[9671],{3905:(e,t,a)=>{a.d(t,{Zo:()=>c,kt:()=>k});var n=a(7294);function i(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function r(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,n)}return a}function l(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?r(Object(a),!0).forEach((function(t){i(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):r(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function o(e,t){if(null==e)return{};var a,n,i=function(e,t){if(null==e)return{};var a,n,i={},r=Object.keys(e);for(n=0;n<r.length;n++)a=r[n],t.indexOf(a)>=0||(i[a]=e[a]);return i}(e,t);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(n=0;n<r.length;n++)a=r[n],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(i[a]=e[a])}return i}var p=n.createContext({}),s=function(e){var t=n.useContext(p),a=t;return e&&(a="function"==typeof e?e(t):l(l({},t),e)),a},c=function(e){var t=s(e.components);return n.createElement(p.Provider,{value:t},e.children)},u="mdxType",m={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},d=n.forwardRef((function(e,t){var a=e.components,i=e.mdxType,r=e.originalType,p=e.parentName,c=o(e,["components","mdxType","originalType","parentName"]),u=s(a),d=i,k=u["".concat(p,".").concat(d)]||u[d]||m[d]||r;return a?n.createElement(k,l(l({ref:t},c),{},{components:a})):n.createElement(k,l({ref:t},c))}));function k(e,t){var a=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var r=a.length,l=new Array(r);l[0]=d;var o={};for(var p in t)hasOwnProperty.call(t,p)&&(o[p]=t[p]);o.originalType=e,o[u]="string"==typeof e?e:i,l[1]=o;for(var s=2;s<r;s++)l[s]=a[s];return n.createElement.apply(null,l)}return n.createElement.apply(null,a)}d.displayName="MDXCreateElement"},9881:(e,t,a)=>{a.r(t),a.d(t,{assets:()=>p,contentTitle:()=>l,default:()=>m,frontMatter:()=>r,metadata:()=>o,toc:()=>s});var n=a(7462),i=(a(7294),a(3905));const r={id:"intro",title:"Introduction",sidebar_label:"Introduction",slug:"/"},l="OPA Gatekeeper Library",o={unversionedId:"intro",id:"intro",title:"Introduction",description:"Artifact Hub",source:"@site/docs/intro.md",sourceDirName:".",slug:"/",permalink:"/gatekeeper-library/website/",draft:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/intro.md",tags:[],version:"current",frontMatter:{id:"intro",title:"Introduction",sidebar_label:"Introduction",slug:"/"},sidebar:"docs",next:{title:"Allowed Repositories",permalink:"/gatekeeper-library/website/validation/allowedrepos"}},p={},s=[{value:"Validation and Mutation",id:"validation-and-mutation",level:2},{value:"Usage",id:"usage",level:2},{value:"kustomize",id:"kustomize",level:3},{value:"kubectl",id:"kubectl",level:3},{value:"Testing",id:"testing",level:2},{value:"How to contribute to the library",id:"how-to-contribute-to-the-library",level:2},{value:"New policy",id:"new-policy",level:3},{value:"Development",id:"development",level:3}],c={toc:s},u="wrapper";function m(e){let{components:t,...a}=e;return(0,i.kt)(u,(0,n.Z)({},c,a,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"opa-gatekeeper-library"},"OPA Gatekeeper Library"),(0,i.kt)("p",null,(0,i.kt)("a",{parentName:"p",href:"https://artifacthub.io/packages/search?repo=gatekeeper-policies"},(0,i.kt)("img",{parentName:"a",src:"https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/gatekeeper-policies",alt:"Artifact Hub"}))),(0,i.kt)("p",null,"A community-owned library of policies for the ",(0,i.kt)("a",{parentName:"p",href:"https://open-policy-agent.github.io/gatekeeper/website/docs/"},"OPA Gatekeeper project"),"."),(0,i.kt)("h2",{id:"validation-and-mutation"},"Validation and Mutation"),(0,i.kt)("p",null,"The library consists of two main components: ",(0,i.kt)("inlineCode",{parentName:"p"},"Validation")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"Mutation"),"."),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"Validation: Gatekeeper can validate resources in the cluster against Gatekeeper validation policies, such as these defined in the library. The policies are defined as ",(0,i.kt)("inlineCode",{parentName:"li"},"ConstraintTemplates")," and ",(0,i.kt)("inlineCode",{parentName:"li"},"Constraints"),". ",(0,i.kt)("inlineCode",{parentName:"li"},"ConstraintTemplates")," can be applied directly to a cluster and then ",(0,i.kt)("inlineCode",{parentName:"li"},"Constraints")," can be applied to customize policy to fit your specific needs."),(0,i.kt)("li",{parentName:"ul"},"Mutation: Gatekeeper can mutate resources in the cluster against the Gatekeeper mutation policies, such as these defined in the library. Mutation policies are only examples, they should be customized to meet your needs before being applied.")),(0,i.kt)("h2",{id:"usage"},"Usage"),(0,i.kt)("h3",{id:"kustomize"},"kustomize"),(0,i.kt)("p",null,"You can use ",(0,i.kt)("a",{parentName:"p",href:"https://kubectl.docs.kubernetes.io/installation/kustomize/"},"kustomize")," to install some or all of the templates alongside your own constraints."),(0,i.kt)("p",null,"First, create a ",(0,i.kt)("inlineCode",{parentName:"p"},"kustomization.yaml")," file:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- github.com/open-policy-agent/gatekeeper-library/library\n# You can optionally install a subset by specifying a subfolder, or specify a commit SHA\n# - github.com/open-policy-agent/gatekeeper-library/library/pod-security-policy?ref=0c82f402fb3594097a90d15215ae223267f5b955\n- constraints.yaml\n")),(0,i.kt)("p",null,"Then define your constraints in a file called ",(0,i.kt)("inlineCode",{parentName:"p"},"constraints.yaml"),' in the same directory. Example constraints can be found in the "samples" folders.'),(0,i.kt)("p",null,"You can install everything with ",(0,i.kt)("inlineCode",{parentName:"p"},"kustomize build . | kubectl apply -f -"),"."),(0,i.kt)("p",null,"More information can be found in the ",(0,i.kt)("a",{parentName:"p",href:"https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/"},"kustomization documentation"),"."),(0,i.kt)("h3",{id:"kubectl"},"kubectl"),(0,i.kt)("p",null,"Instead of using kustomize, you can directly apply the ",(0,i.kt)("inlineCode",{parentName:"p"},"template.yaml")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"constraint.yaml")," provided in each directory under ",(0,i.kt)("inlineCode",{parentName:"p"},"library/")),(0,i.kt)("p",null,"For example"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"cd library/general/httpsonly/\nkubectl apply -f template.yaml\nkubectl apply -f samples/ingress-https-only/constraint.yaml\nkubectl apply -f library/general/httpsonly/sync.yaml # optional: when GK is running with OPA cache\n")),(0,i.kt)("h2",{id:"testing"},"Testing"),(0,i.kt)("p",null,"The ",(0,i.kt)("inlineCode",{parentName:"p"},"suite.yaml")," files define test cases for each ConstraintTemplate in the library.\nChanges to gatekeeper-library ConstraintTemplates may be tested with the gator CLI:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"gatekeeper-library$ gator verify ./...\n")),(0,i.kt)("p",null,"The gator CLI may be downloaded from the Gatekeeper\n",(0,i.kt)("a",{parentName:"p",href:"https://github.com/open-policy-agent/gatekeeper/releases"},"releases page"),"."),(0,i.kt)("h2",{id:"how-to-contribute-to-the-library"},"How to contribute to the library"),(0,i.kt)("h3",{id:"new-policy"},"New policy"),(0,i.kt)("p",null,"If you have a policy you would like to contribute, please submit a pull request.\nEach new policy should contain:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"A constraint template named ",(0,i.kt)("inlineCode",{parentName:"li"},"src/<policy-name>/constraint.tmpl")," with a ",(0,i.kt)("inlineCode",{parentName:"li"},"description")," annotation and the parameter structure, if any, defined in ",(0,i.kt)("inlineCode",{parentName:"li"},"spec.crd.spec.validation.openAPIV3Schema"),". The template is rendered using ",(0,i.kt)("a",{parentName:"li",href:"https://docs.gomplate.ca/"},"gomplate"),"."),(0,i.kt)("li",{parentName:"ul"},"One or more sample constraints, each with an example of an allowed (",(0,i.kt)("inlineCode",{parentName:"li"},"example_allowed.yaml"),") and disallowed (",(0,i.kt)("inlineCode",{parentName:"li"},"example_disallowed.yaml"),") resource under ",(0,i.kt)("inlineCode",{parentName:"li"},"library/<policy-name>/samples/<policy-name>")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"kustomization.yaml")," and ",(0,i.kt)("inlineCode",{parentName:"li"},"suite.yaml")," under ",(0,i.kt)("inlineCode",{parentName:"li"},"library/<policy-name>")),(0,i.kt)("li",{parentName:"ul"},"The rego source, as ",(0,i.kt)("inlineCode",{parentName:"li"},"src.rego")," and unit tests as ",(0,i.kt)("inlineCode",{parentName:"li"},"src_test.rego")," in the corresponding subdirectory under ",(0,i.kt)("inlineCode",{parentName:"li"},"src/<policy-name>")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://docs.google.com/document/d/1IYiypA-mRcdfSVfmoeyuaeG8XtA1u4GkcqH3kEkv2uw/edit"},"Versioning")," has been introduced for Gatekeeper Library policies. Please make sure to add or bump the version of the policy as per the guidelines in the ",(0,i.kt)("inlineCode",{parentName:"li"},"src/<policy-name>/constraint.tmpl")," annotation.",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},"Major version bump required: Whenever there is a breaking change in the policy e.g.  updating template Kind, parameter schema, or any other breaking changes"),(0,i.kt)("li",{parentName:"ul"},"Minor version bump required: Whenever there is a backward compatible change in the policy e.g. adding a parameter, updating Rego logic"),(0,i.kt)("li",{parentName:"ul"},"Patch version bump required: Whenever there is a simple backward compatible change in the policy, e.g. Simple Rego fix, updating policy metadata")))),(0,i.kt)("h3",{id:"development"},"Development"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"policy code and tests are maintained in ",(0,i.kt)("inlineCode",{parentName:"li"},"src/<policy-name>/src.rego")," and ",(0,i.kt)("inlineCode",{parentName:"li"},"src/<policy-name>/src_test.rego")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"make generate")," will generate ",(0,i.kt)("inlineCode",{parentName:"li"},"library/<policy-name>/template.yaml")," from ",(0,i.kt)("inlineCode",{parentName:"li"},"src/<policy-name>/src.rego")," using ",(0,i.kt)("a",{parentName:"li",href:"https://docs.gomplate.ca/"},"gomplate"),"."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"make generate-website-docs")," will generate the markdown files required for the website."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"make generate-artifacthub-artifacts")," will generate or update the artifact hub packages and associated ",(0,i.kt)("inlineCode",{parentName:"li"},"artifacthub-pkg.yml")," file under ",(0,i.kt)("inlineCode",{parentName:"li"},"/artifacthub")," directory."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"make generate-all")," will generate all artifacts above."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"make validate")," will run validation checks on the library repo. Currently it validates directory structure of ",(0,i.kt)("inlineCode",{parentName:"li"},"website/docs")," directory."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"make unit-test")," will run all unit tests in the scripts directory."),(0,i.kt)("li",{parentName:"ul"},"run all tests with ",(0,i.kt)("inlineCode",{parentName:"li"},"./test.sh")),(0,i.kt)("li",{parentName:"ul"},"run single test with ",(0,i.kt)("inlineCode",{parentName:"li"},"opa test src/<folder>/src.rego src/<folder>/src_test.rego --verbose")),(0,i.kt)("li",{parentName:"ul"},"print results with ",(0,i.kt)("inlineCode",{parentName:"li"},'trace(sprintf("%v", [thing]))'))))}m.isMDXComponent=!0}}]);