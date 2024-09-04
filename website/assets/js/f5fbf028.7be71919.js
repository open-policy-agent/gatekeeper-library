"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[3741],{2915:(e,n,a)=>{a.r(n),a.d(n,{assets:()=>r,contentTitle:()=>i,default:()=>u,frontMatter:()=>o,metadata:()=>l,toc:()=>c});var s=a(5893),t=a(1151);const o={id:"disallowanonymous",title:"Disallow Anonymous Access"},i="Disallow Anonymous Access",l={id:"validation/disallowanonymous",title:"Disallow Anonymous Access",description:"Description",source:"@site/docs/validation/disallowanonymous.md",sourceDirName:"validation",slug:"/validation/disallowanonymous",permalink:"/gatekeeper-library/website/validation/disallowanonymous",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/disallowanonymous.md",tags:[],version:"current",frontMatter:{id:"disallowanonymous",title:"Disallow Anonymous Access"},sidebar:"docs",previous:{title:"Required Resources",permalink:"/gatekeeper-library/website/validation/containerresources"},next:{title:"Disallowed Repositories",permalink:"/gatekeeper-library/website/validation/disallowedrepos"}},r={},c=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function d(e){const n={code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,t.a)(),...e.components},{Details:a}=n;return a||function(e,n){throw new Error("Expected "+(n?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(n.h1,{id:"disallow-anonymous-access",children:"Disallow Anonymous Access"}),"\n",(0,s.jsx)(n.h2,{id:"description",children:"Description"}),"\n",(0,s.jsxs)(n.p,{children:["Disallows associating ClusterRole and Role resources to the system",":anonymous"," user and system",":unauthenticated"," group."]}),"\n",(0,s.jsx)(n.h2,{id:"template",children:"Template"}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8sdisallowanonymous\n  annotations:\n    metadata.gatekeeper.sh/title: "Disallow Anonymous Access"\n    metadata.gatekeeper.sh/version: 1.1.0\n    description: Disallows associating ClusterRole and Role resources to the system:anonymous user and system:unauthenticated group.\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sDisallowAnonymous\n      validation:\n        # Schema for the `parameters` field\n        openAPIV3Schema:\n          type: object\n          properties:\n            allowedRoles:\n              description: >-\n                The list of ClusterRoles and Roles that may be associated\n                with the `system:unauthenticated` group and `system:anonymous`\n                user.\n              type: array\n              items:\n                type: string\n            disallowAuthenticated:\n              description: >-\n                A boolean indicating whether `system:authenticated` should also\n                be disallowed by this policy.\n              type: boolean\n              default: false\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      rego: |\n        package k8sdisallowanonymous\n\n        violation[{"msg": msg}] {\n          not is_allowed(input.review.object.roleRef, object.get(input, ["parameters", "allowedRoles"], []))\n\n          group := ["system:unauthenticated", "system:anonymous"][_]\n          subject_is(input.review.object.subjects[_], group)\n\n          msg := message(group)\n        }\n\n        violation[{"msg": msg}] {\n          not is_allowed(input.review.object.roleRef, object.get(input, ["parameters", "allowedRoles"], []))\n\n          object.get(input, ["parameters", "disallowAuthenticated"], false)\n\n          group := "system:authenticated"\n          subject_is(input.review.object.subjects[_], group)\n\n          msg := message(group)\n        }\n\n        is_allowed(role, allowedRoles) {\n          role.name == allowedRoles[_]\n        }\n\n        subject_is(subject, expected) {\n          subject.name == expected\n        }\n\n        message(name) := val {\n          val := sprintf("%v is not allowed as a subject name in %v %v", [name, input.review.object.kind, input.review.object.metadata.name])\n        }\n\n'})}),"\n",(0,s.jsx)(n.h3,{id:"usage",children:"Usage"}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowanonymous/template.yaml\n"})}),"\n",(0,s.jsx)(n.h2,{id:"examples",children:"Examples"}),"\n",(0,s.jsxs)(a,{children:[(0,s.jsx)("summary",{children:"disallow-anonymous"}),(0,s.jsxs)(a,{children:[(0,s.jsx)("summary",{children:"constraint"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sDisallowAnonymous\nmetadata:\n  name: no-anonymous\nspec:\n  match:\n    kinds:\n      - apiGroups: ["rbac.authorization.k8s.io"]\n        kinds: ["ClusterRoleBinding"]\n      - apiGroups: ["rbac.authorization.k8s.io"]\n        kinds: ["RoleBinding"]\n  parameters:\n    allowedRoles: \n      - cluster-role-1\n\n'})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowanonymous/samples/no-anonymous-bindings/constraint.yaml\n"})})]}),(0,s.jsxs)(a,{children:[(0,s.jsx)("summary",{children:"example-allowed"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: cluster-role-binding-1\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-role-1\nsubjects:\n- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: system:authenticated\n- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: system:unauthenticated\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowanonymous/samples/no-anonymous-bindings/example_allowed.yaml\n"})})]}),(0,s.jsxs)(a,{children:[(0,s.jsx)("summary",{children:"example-disallowed"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: cluster-role-binding-2\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-role-2\nsubjects:\n- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: system:authenticated\n- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: system:unauthenticated\n- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: system:anonymous\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowanonymous/samples/no-anonymous-bindings/example_disallowed.yaml\n"})})]})]}),"\n",(0,s.jsxs)(a,{children:[(0,s.jsx)("summary",{children:"disallow-authenticated"}),(0,s.jsxs)(a,{children:[(0,s.jsx)("summary",{children:"constraint"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sDisallowAnonymous\nmetadata:\n  name: no-anonymous\nspec:\n  match:\n    kinds:\n      - apiGroups: ["rbac.authorization.k8s.io"]\n        kinds: ["ClusterRoleBinding"]\n      - apiGroups: ["rbac.authorization.k8s.io"]\n        kinds: ["RoleBinding"]\n  parameters:\n    disallowAuthenticated: true\n\n'})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowanonymous/samples/no-authenticated/constraint.yaml\n"})})]}),(0,s.jsxs)(a,{children:[(0,s.jsx)("summary",{children:"authenticated-disallowed-with-parameter-true"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",children:"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: cluster-role-binding-2\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-role-2\nsubjects:\n- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: system:authenticated\n- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: system:unauthenticated\n- apiGroup: rbac.authorization.k8s.io\n  kind: Group\n  name: system:anonymous\n\n"})}),(0,s.jsx)(n.p,{children:"Usage"}),(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowanonymous/samples/no-anonymous-bindings/example_disallowed.yaml\n"})})]})]})]})}function u(e={}){const{wrapper:n}={...(0,t.a)(),...e.components};return n?(0,s.jsx)(n,{...e,children:(0,s.jsx)(d,{...e})}):d(e)}},1151:(e,n,a)=>{a.d(n,{Z:()=>l,a:()=>i});var s=a(7294);const t={},o=s.createContext(t);function i(e){const n=s.useContext(o);return s.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function l(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(t):e.components||t:i(e.components),s.createElement(o.Provider,{value:n},e.children)}}}]);