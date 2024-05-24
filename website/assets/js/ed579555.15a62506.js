"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[8626],{4722:(e,a,n)=>{n.r(a),n.d(a,{assets:()=>o,contentTitle:()=>t,default:()=>c,frontMatter:()=>r,metadata:()=>i,toc:()=>d});var s=n(5893),l=n(1151);const r={id:"requiredlabels",title:"Required Labels"},t="Required Labels",i={id:"validation/requiredlabels",title:"Required Labels",description:"Description",source:"@site/docs/validation/requiredlabels.md",sourceDirName:"validation",slug:"/validation/requiredlabels",permalink:"/gatekeeper-library/website/validation/requiredlabels",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/requiredlabels.md",tags:[],version:"current",frontMatter:{id:"requiredlabels",title:"Required Labels"},sidebar:"docs",previous:{title:"Required Annotations",permalink:"/gatekeeper-library/website/validation/requiredannotations"},next:{title:"Required Probes",permalink:"/gatekeeper-library/website/validation/requiredprobes"}},o={},d=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function p(e){const a={code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,l.a)(),...e.components},{Details:n}=a;return n||function(e,a){throw new Error("Expected "+(a?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(a.h1,{id:"required-labels",children:"Required Labels"}),"\n",(0,s.jsx)(a.h2,{id:"description",children:"Description"}),"\n",(0,s.jsx)(a.p,{children:"Requires resources to contain specified labels, with values matching provided regular expressions."}),"\n",(0,s.jsx)(a.h2,{id:"template",children:"Template"}),"\n",(0,s.jsx)(a.pre,{children:(0,s.jsx)(a.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8srequiredlabels\n  annotations:\n    metadata.gatekeeper.sh/title: "Required Labels"\n    metadata.gatekeeper.sh/version: 1.1.1\n    description: >-\n      Requires resources to contain specified labels, with values matching\n      provided regular expressions.\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sRequiredLabels\n      validation:\n        openAPIV3Schema:\n          type: object\n          properties:\n            message:\n              type: string\n            labels:\n              type: array\n              description: >-\n                A list of labels and values the object must specify.\n              items:\n                type: object\n                properties:\n                  key:\n                    type: string\n                    description: >-\n                      The required label.\n                  allowedRegex:\n                    type: string\n                    description: >-\n                      If specified, a regular expression the annotation\'s value\n                      must match. The value must contain at least one match for\n                      the regular expression.\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      code:\n      - engine: K8sNativeValidation\n        source:\n          validations:\n          - expression: \'(has(variables.anyObject.metadata) && variables.params.labels.all(entry, has(variables.anyObject.metadata.labels) && entry.key in variables.anyObject.metadata.labels))\'\n            messageExpression: \'"missing required label, requires all of: " + variables.params.labels.map(entry, entry.key).join(", ")\'\n          - expression: \'(has(variables.anyObject.metadata) && variables.params.labels.all(entry, has(variables.anyObject.metadata.labels) && entry.key in variables.anyObject.metadata.labels && string(variables.anyObject.metadata.labels[entry.key]).matches(string(entry.allowedRegex))))\'\n            message: "regex mismatch"\n      - engine: Rego\n        source:\n          rego: |\n            package k8srequiredlabels\n\n            get_message(parameters, _default) := _default {\n              not parameters.message\n            }\n\n            get_message(parameters, _) := parameters.message\n\n            violation[{"msg": msg, "details": {"missing_labels": missing}}] {\n              provided := {label | input.review.object.metadata.labels[label]}\n              required := {label | label := input.parameters.labels[_].key}\n              missing := required - provided\n              count(missing) > 0\n              def_msg := sprintf("you must provide labels: %v", [missing])\n              msg := get_message(input.parameters, def_msg)\n            }\n\n            violation[{"msg": msg}] {\n              value := input.review.object.metadata.labels[key]\n              expected := input.parameters.labels[_]\n              expected.key == key\n              # do not match if allowedRegex is not defined, or is an empty string\n              expected.allowedRegex != ""\n              not regex.match(expected.allowedRegex, value)\n              def_msg := sprintf("Label <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])\n              msg := get_message(input.parameters, def_msg)\n            }\n\n\n'})}),"\n",(0,s.jsx)(a.h3,{id:"usage",children:"Usage"}),"\n",(0,s.jsx)(a.pre,{children:(0,s.jsx)(a.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/template.yaml\n"})}),"\n",(0,s.jsx)(a.h2,{id:"examples",children:"Examples"}),"\n",(0,s.jsxs)(n,{children:[(0,s.jsx)("summary",{children:"must-have-owner"}),(0,s.jsxs)(n,{children:[(0,s.jsx)("summary",{children:"constraint"}),(0,s.jsx)(a.pre,{children:(0,s.jsx)(a.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sRequiredLabels\nmetadata:\n  name: all-must-have-owner\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Namespace"]\n  parameters:\n    message: "All namespaces must have an `owner` label that points to your company username"\n    labels:\n      - key: owner\n        allowedRegex: "^[a-zA-Z]+.agilebank.demo$"\n\n'})}),(0,s.jsx)(a.p,{children:"Usage"}),(0,s.jsx)(a.pre,{children:(0,s.jsx)(a.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/all-must-have-owner/constraint.yaml\n"})})]}),(0,s.jsxs)(n,{children:[(0,s.jsx)("summary",{children:"example-allowed"}),(0,s.jsx)(a.pre,{children:(0,s.jsx)(a.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: allowed-namespace\n  labels:\n    owner: user.agilebank.demo\n\n"})}),(0,s.jsx)(a.p,{children:"Usage"}),(0,s.jsx)(a.pre,{children:(0,s.jsx)(a.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/all-must-have-owner/example_allowed.yaml\n"})})]}),(0,s.jsxs)(n,{children:[(0,s.jsx)("summary",{children:"example-disallowed"}),(0,s.jsx)(a.pre,{children:(0,s.jsx)(a.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: disallowed-namespace\n\n"})}),(0,s.jsx)(a.p,{children:"Usage"}),(0,s.jsx)(a.pre,{children:(0,s.jsx)(a.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/all-must-have-owner/example_disallowed.yaml\n"})})]}),(0,s.jsxs)(n,{children:[(0,s.jsx)("summary",{children:"example-disallowed-label-value"}),(0,s.jsx)(a.pre,{children:(0,s.jsx)(a.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: disallowed-namespace\n  labels:\n    owner: user\n\n"})}),(0,s.jsx)(a.p,{children:"Usage"}),(0,s.jsx)(a.pre,{children:(0,s.jsx)(a.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/all-must-have-owner/example_disallowed_label_value.yaml\n"})})]})]})]})}function c(e={}){const{wrapper:a}={...(0,l.a)(),...e.components};return a?(0,s.jsx)(a,{...e,children:(0,s.jsx)(p,{...e})}):p(e)}},1151:(e,a,n)=>{n.d(a,{Z:()=>i,a:()=>t});var s=n(7294);const l={},r=s.createContext(l);function t(e){const a=s.useContext(r);return s.useMemo((function(){return"function"==typeof e?e(a):{...a,...e}}),[a,e])}function i(e){let a;return a=e.disableParentContext?"function"==typeof e.components?e.components(l):e.components||l:t(e.components),s.createElement(r.Provider,{value:a},e.children)}}}]);