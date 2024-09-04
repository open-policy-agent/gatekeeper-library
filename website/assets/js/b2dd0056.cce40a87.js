"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[7014],{2843:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>r,contentTitle:()=>l,default:()=>c,frontMatter:()=>o,metadata:()=>i,toc:()=>p});var a=t(5893),s=t(1151);const o={id:"host-filesystem",title:"Host Filesystem"},l="Host Filesystem",i={id:"validation/host-filesystem",title:"Host Filesystem",description:"Description",source:"@site/docs/validation/host-filesystem.md",sourceDirName:"validation",slug:"/validation/host-filesystem",permalink:"/gatekeeper-library/website/validation/host-filesystem",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/host-filesystem.md",tags:[],version:"current",frontMatter:{id:"host-filesystem",title:"Host Filesystem"},sidebar:"docs",previous:{title:"FS Group",permalink:"/gatekeeper-library/website/validation/fsgroup"},next:{title:"Host Namespace",permalink:"/gatekeeper-library/website/validation/host-namespaces"}},r={},p=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function h(e){const n={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,s.a)(),...e.components},{Details:t}=n;return t||function(e,n){throw new Error("Expected "+(n?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,a.jsxs)(a.Fragment,{children:[(0,a.jsx)(n.h1,{id:"host-filesystem",children:"Host Filesystem"}),"\n",(0,a.jsx)(n.h2,{id:"description",children:"Description"}),"\n",(0,a.jsxs)(n.p,{children:["Controls usage of the host filesystem. Corresponds to the ",(0,a.jsx)(n.code,{children:"allowedHostPaths"})," field in a PodSecurityPolicy. For more information, see ",(0,a.jsx)(n.a,{href:"https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems",children:"https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems"})]}),"\n",(0,a.jsx)(n.h2,{id:"template",children:"Template"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8spsphostfilesystem\n  annotations:\n    metadata.gatekeeper.sh/title: "Host Filesystem"\n    metadata.gatekeeper.sh/version: 1.1.0\n    description: >-\n      Controls usage of the host filesystem. Corresponds to the\n      `allowedHostPaths` field in a PodSecurityPolicy. For more information,\n      see\n      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sPSPHostFilesystem\n      validation:\n        # Schema for the `parameters` field\n        openAPIV3Schema:\n          type: object\n          description: >-\n            Controls usage of the host filesystem. Corresponds to the\n            `allowedHostPaths` field in a PodSecurityPolicy. For more information,\n            see\n            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems\n          properties:\n            allowedHostPaths:\n              type: array\n              description: "An array of hostpath objects, representing paths and read/write configuration."\n              items:\n                type: object\n                properties:\n                  pathPrefix:\n                    type: string\n                    description: "The path prefix that the host volume must match."\n                  readOnly:\n                    type: boolean\n                    description: "when set to true, any container volumeMounts matching the pathPrefix must include `readOnly: true`."\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      code:\n      - engine: K8sNativeValidation\n        source: \n          variables:\n          - name: containers\n            expression: \'has(variables.anyObject.spec.containers) ? variables.anyObject.spec.containers : []\'\n          - name: initContainers\n            expression: \'has(variables.anyObject.spec.initContainers) ? variables.anyObject.spec.initContainers : []\'\n          - name: ephemeralContainers\n            expression: \'has(variables.anyObject.spec.ephemeralContainers) ? variables.anyObject.spec.ephemeralContainers : []\'\n          - name: allContainers\n            expression: \'variables.containers + variables.initContainers + variables.ephemeralContainers\'\n          - name: allowedPaths\n            expression: |\n              !has(variables.params.allowedHostPaths) ? [] : variables.params.allowedHostPaths\n          - name: volumes\n            expression: |\n              variables.anyObject.spec.volumes.filter(volume, has(volume.hostPath))\n          - name: badHostPaths\n            expression: |\n              variables.volumes.filter(volume, \n                (size(variables.allowedPaths) == 0) ||\n                !(variables.allowedPaths.exists(allowedPath, \n                    volume.hostPath.path.startsWith(allowedPath.pathPrefix) && (\n                    (!has(allowedPath.readOnly) || !(allowedPath.readOnly)) ||\n                      (has(allowedPath.readOnly) && allowedPath.readOnly && !variables.allContainers.exists(c, \n                      c.volumeMounts.exists(m, m.name == volume.name && (!has(m.readOnly) || !m.readOnly)))))))\n              ).map(volume, "{ hostPath: { path : " + volume.hostPath.path + " }, name: " + volume.name + "}").map(volume, "HostPath volume " + volume + " is not allowed, pod: " + object.metadata.name + ". Allowed path: " + variables.allowedPaths.map(path,  path.pathPrefix + ", readOnly: " + (path.readOnly ? "true" : "false") + "}").join(", "))\n          validations:\n          - expression: \'(has(request.operation) && request.operation == "UPDATE") || size(variables.badHostPaths) == 0\'\n            messageExpression: \'variables.badHostPaths.join("\\n")\'\n      - engine: Rego\n        source:\n          rego: |\n            package k8spsphostfilesystem\n\n            import data.lib.exclude_update.is_update\n\n            violation[{"msg": msg, "details": {}}] {\n                # spec.volumes field is immutable.\n                not is_update(input.review)\n\n                volume := input_hostpath_volumes[_]\n                allowedPaths := get_allowed_paths(input)\n                input_hostpath_violation(allowedPaths, volume)\n                msg := sprintf("HostPath volume %v is not allowed, pod: %v. Allowed path: %v", [volume, input.review.object.metadata.name, allowedPaths])\n            }\n\n            input_hostpath_violation(allowedPaths, _) {\n                # An empty list means all host paths are blocked\n                allowedPaths == []\n            }\n            input_hostpath_violation(allowedPaths, volume) {\n                not input_hostpath_allowed(allowedPaths, volume)\n            }\n\n            get_allowed_paths(arg) = out {\n                not arg.parameters\n                out = []\n            }\n            get_allowed_paths(arg) = out {\n                not arg.parameters.allowedHostPaths\n                out = []\n            }\n            get_allowed_paths(arg) = out {\n                out = arg.parameters.allowedHostPaths\n            }\n\n            input_hostpath_allowed(allowedPaths, volume) {\n                allowedHostPath := allowedPaths[_]\n                path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)\n                not allowedHostPath.readOnly == true\n            }\n\n            input_hostpath_allowed(allowedPaths, volume) {\n                allowedHostPath := allowedPaths[_]\n                path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)\n                allowedHostPath.readOnly\n                not writeable_input_volume_mounts(volume.name)\n            }\n\n            writeable_input_volume_mounts(volume_name) {\n                container := input_containers[_]\n                mount := container.volumeMounts[_]\n                mount.name == volume_name\n                not mount.readOnly\n            }\n\n            # This allows "/foo", "/foo/", "/foo/bar" etc., but\n            # disallows "/fool", "/etc/foo" etc.\n            path_matches(prefix, path) {\n                a := path_array(prefix)\n                b := path_array(path)\n                prefix_matches(a, b)\n            }\n            path_array(p) = out {\n                p != "/"\n                out := split(trim(p, "/"), "/")\n            }\n            # This handles the special case for "/", since\n            # split(trim("/", "/"), "/") == [""]\n            path_array("/") = []\n\n            prefix_matches(a, b) {\n                count(a) <= count(b)\n                not any_not_equal_upto(a, b, count(a))\n            }\n\n            any_not_equal_upto(a, b, n) {\n                a[i] != b[i]\n                i < n\n            }\n\n            input_hostpath_volumes[v] {\n                v := input.review.object.spec.volumes[_]\n                has_field(v, "hostPath")\n            }\n\n            # has_field returns whether an object has a field\n            has_field(object, field) = true {\n                object[field]\n            }\n            input_containers[c] {\n                c := input.review.object.spec.containers[_]\n            }\n\n            input_containers[c] {\n                c := input.review.object.spec.initContainers[_]\n            }\n\n            input_containers[c] {\n                c := input.review.object.spec.ephemeralContainers[_]\n            }\n          libs:\n            - |\n              package lib.exclude_update\n\n              is_update(review) {\n                  review.operation == "UPDATE"\n              }\n\n'})}),"\n",(0,a.jsx)(n.h3,{id:"usage",children:"Usage"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/template.yaml\n"})}),"\n",(0,a.jsx)(n.h2,{id:"examples",children:"Examples"}),"\n",(0,a.jsxs)(t,{children:[(0,a.jsx)("summary",{children:"host-filesystem"}),(0,a.jsxs)(t,{children:[(0,a.jsx)("summary",{children:"constraint"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sPSPHostFilesystem\nmetadata:\n  name: psp-host-filesystem\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    allowedHostPaths:\n    - readOnly: true\n      pathPrefix: "/foo"\n\n'})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/psp-host-filesystem/constraint.yaml\n"})})]}),(0,a.jsxs)(t,{children:[(0,a.jsx)("summary",{children:"example-disallowed"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-filesystem\nspec:\n  containers:\n  - name: nginx\n    image: nginx\n    volumeMounts:\n    - mountPath: /cache\n      name: cache-volume\n      readOnly: true\n  volumes:\n  - name: cache-volume\n    hostPath:\n      path: /tmp # directory location on host\n\n"})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/psp-host-filesystem/example_disallowed.yaml\n"})})]}),(0,a.jsxs)(t,{children:[(0,a.jsx)("summary",{children:"example-allowed"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-filesystem\nspec:\n  containers:\n    - name: nginx\n      image: nginx\n      volumeMounts:\n        - mountPath: /cache\n          name: cache-volume\n          readOnly: true\n  volumes:\n    - name: cache-volume\n      hostPath:\n        path: /foo/bar\n\n"})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/psp-host-filesystem/example_allowed.yaml\n"})})]}),(0,a.jsxs)(t,{children:[(0,a.jsx)("summary",{children:"disallowed-ephemeral"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-host-filesystem\nspec:\n  ephemeralContainers:\n  - name: nginx\n    image: nginx\n    volumeMounts:\n    - mountPath: /cache\n      name: cache-volume\n      readOnly: true\n  volumes:\n  - name: cache-volume\n    hostPath:\n      path: /tmp # directory location on host\n\n"})}),(0,a.jsx)(n.p,{children:"Usage"}),(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/psp-host-filesystem/disallowed_ephemeral.yaml\n"})})]})]})]})}function c(e={}){const{wrapper:n}={...(0,s.a)(),...e.components};return n?(0,a.jsx)(n,{...e,children:(0,a.jsx)(h,{...e})}):h(e)}},1151:(e,n,t)=>{t.d(n,{Z:()=>i,a:()=>l});var a=t(7294);const s={},o=a.createContext(s);function l(e){const n=a.useContext(o);return a.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function i(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(s):e.components||s:l(e.components),a.createElement(o.Provider,{value:n},e.children)}}}]);