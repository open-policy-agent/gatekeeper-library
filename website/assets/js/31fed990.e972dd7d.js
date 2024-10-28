"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[5019],{1849:(e,n,i)=>{i.r(n),i.d(n,{assets:()=>r,contentTitle:()=>l,default:()=>m,frontMatter:()=>t,metadata:()=>s,toc:()=>c});var o=i(5893),a=i(1151);const t={id:"seccompv2",title:"Seccomp V2"},l="Seccomp V2",s={id:"validation/seccompv2",title:"Seccomp V2",description:"Description",source:"@site/docs/validation/seccompv2.md",sourceDirName:"validation",slug:"/validation/seccompv2",permalink:"/gatekeeper-library/website/validation/seccompv2",draft:!1,unlisted:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper-library/edit/master/website/docs/validation/seccompv2.md",tags:[],version:"current",frontMatter:{id:"seccompv2",title:"Seccomp V2"},sidebar:"docs",previous:{title:"Seccomp",permalink:"/gatekeeper-library/website/validation/seccomp"},next:{title:"SELinux V2",permalink:"/gatekeeper-library/website/validation/selinux"}},r={},c=[{value:"Description",id:"description",level:2},{value:"Template",id:"template",level:2},{value:"Usage",id:"usage",level:3},{value:"Examples",id:"examples",level:2}];function p(e){const n={code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",pre:"pre",...(0,a.a)(),...e.components},{Details:i}=n;return i||function(e,n){throw new Error("Expected "+(n?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,o.jsxs)(o.Fragment,{children:[(0,o.jsx)(n.h1,{id:"seccomp-v2",children:"Seccomp V2"}),"\n",(0,o.jsx)(n.h2,{id:"description",children:"Description"}),"\n",(0,o.jsxs)(n.p,{children:["Controls the seccomp profile used by containers. Corresponds to the ",(0,o.jsx)(n.code,{children:"securityContext.seccompProfile"})," field. Security contexts from the annotation is not considered as Kubernetes no longer reads security contexts from the annotation."]}),"\n",(0,o.jsx)(n.h2,{id:"template",children:"Template"}),"\n",(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-yaml",children:'apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata:\n  name: k8spspseccompv2\n  annotations:\n    metadata.gatekeeper.sh/title: "Seccomp V2"\n    metadata.gatekeeper.sh/version: 1.0.0\n    description: >-\n      Controls the seccomp profile used by containers. Corresponds to the\n      `securityContext.seccompProfile` field. Security contexts from the annotation is not considered as Kubernetes no longer reads security contexts from the annotation.\nspec:\n  crd:\n    spec:\n      names:\n        kind: K8sPSPSeccompV2\n      validation:\n        # Schema for the `parameters` field\n        openAPIV3Schema:\n          type: object\n          description: >-\n            Controls the seccomp profile used by containers. Corresponds to the\n            `securityContext.seccompProfile` field. Security contexts from the annotation is not considered as Kubernetes no longer reads security contexts from the annotation.\n          properties:\n            exemptImages:\n              description: >-\n                Any container that uses an image that matches an entry in this list will be excluded\n                from enforcement. Prefix-matching can be signified with `*`. For example: `my-image-*`.\n\n                It is recommended that users use the fully-qualified Docker image name (e.g. start with a domain name)\n                in order to avoid unexpectedly exempting images from an untrusted repository.\n              type: array\n              items:\n                type: string\n            allowedProfiles:\n              type: array\n              description: >-\n                An array of allowed profile values for seccomp on Pods/Containers.\n\n                Can use the securityContext naming scheme: `RuntimeDefault`, `Unconfined`\n                and/or `Localhost`. For securityContext `Localhost`, use the parameter `allowedLocalhostFiles`\n                to list the allowed profile JSON files.\n\n                The policy code will translate between the two schemes so it is not necessary to use both.\n\n                Putting a `*` in this array allows all Profiles to be used.\n\n                This field is required since with an empty list this policy will block all workloads.\n              items:\n                type: string\n            allowedLocalhostFiles:\n              type: array\n              description: >-\n                When using securityContext naming scheme for seccomp and including `Localhost` this array holds\n                the allowed profile JSON files.\n\n                Putting a `*` in this array will allows all JSON files to be used.\n\n                This field is required to allow `Localhost` in securityContext as with an empty list it will block.\n              items:\n                type: string\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      code: \n      - engine: K8sNativeValidation\n        source:\n          variables:\n          - name: containers\n            expression: \'has(variables.anyObject.spec.containers) ? variables.anyObject.spec.containers : []\'\n          - name: initContainers\n            expression: \'has(variables.anyObject.spec.initContainers) ? variables.anyObject.spec.initContainers : []\'\n          - name: ephemeralContainers\n            expression: \'has(variables.anyObject.spec.ephemeralContainers) ? variables.anyObject.spec.ephemeralContainers : []\'\n          - name: allowAllProfiles\n            expression: |\n              has(variables.params.allowedProfiles) && variables.params.allowedProfiles.exists(profile, profile == "*")\n          - name: exemptImagePrefixes\n            expression: |\n              !has(variables.params.exemptImages) ? [] :\n                variables.params.exemptImages.filter(image, image.endsWith("*")).map(image, string(image).replace("*", ""))\n          - name: exemptImageExplicit\n            expression: |\n              !has(variables.params.exemptImages) ? [] : \n                variables.params.exemptImages.filter(image, !image.endsWith("*"))\n          - name: exemptImages\n            expression: |\n              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,\n                container.image in variables.exemptImageExplicit ||\n                variables.exemptImagePrefixes.exists(exemption, string(container.image).startsWith(exemption))).map(container, container.image)\n          - name: unverifiedContainers\n            expression: |\n              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,\n                !variables.allowAllProfiles &&\n                !(container.image in variables.exemptImages))\n          - name: inputNonLocalHostProfiles\n            expression: |\n              variables.params.allowedProfiles.filter(profile, profile != "Localhost").map(profile, {"type": profile})\n          - name: inputLocalHostProfiles\n            expression: |\n              variables.params.allowedProfiles.exists(profile, profile == "Localhost") ? variables.params.allowedLocalhostFiles.map(file, {"type": "Localhost", "localHostProfile": string(file)}) : []\n          - name: inputAllowedProfiles\n            expression: |\n              variables.inputNonLocalHostProfiles + variables.inputLocalHostProfiles\n          - name: hasPodSeccomp\n            expression: |\n              has(variables.anyObject.spec.securityContext) && has(variables.anyObject.spec.securityContext.seccompProfile)\n          - name: podLocalHostProfile\n            expression: |\n              variables.hasPodSeccomp && has(variables.anyObject.spec.securityContext.seccompProfile.localhostProfile) ? variables.anyObject.spec.securityContext.seccompProfile.localhostProfile : ""\n          - name: podSecurityContextProfileType\n            expression: |\n              has(variables.hasPodSeccomp) && has(variables.anyObject.spec.securityContext.seccompProfile.type) ? variables.anyObject.spec.securityContext.seccompProfile.type\n                : ""\n          - name: podSecurityContextProfiles\n            expression: |\n              variables.unverifiedContainers.filter(container, \n                !(has(container.securityContext) && has(container.securityContext.seccompProfile)) && \n                variables.hasPodSeccomp\n              ).map(container, {\n                "container" : container.name,\n                "profile" : dyn(variables.podSecurityContextProfileType),\n                "file" : variables.podLocalHostProfile,\n                "location" : dyn("pod securityContext"),\n              })\n          - name: containerSecurityContextProfiles\n            expression: |\n              variables.unverifiedContainers.filter(container, \n                has(container.securityContext) && has(container.securityContext.seccompProfile)\n              ).map(container, {\n                "container" : container.name,\n                "profile" : dyn(container.securityContext.seccompProfile.type),\n                "file" : has(container.securityContext.seccompProfile.localhostProfile) ? container.securityContext.seccompProfile.localhostProfile : dyn(""),\n                "location" : dyn("container securityContext"),\n              })\n          - name: containerProfilesMissing\n            expression: |\n              variables.unverifiedContainers.filter(container, \n                !(has(container.securityContext) && has(container.securityContext.seccompProfile)) && \n                !variables.hasPodSeccomp\n              ).map(container, {\n                "container" : container.name,\n                "profile" : dyn("not configured"),\n                "file" : dyn(""),\n                "location" : dyn("no explicit profile found"),\n              })\n          - name: allContainerProfiles\n            expression: |\n              variables.podSecurityContextProfiles + variables.containerSecurityContextProfiles + variables.containerProfilesMissing\n          - name: badContainerProfilesWithoutFiles\n            expression: |\n              variables.allContainerProfiles.filter(container, \n                  container.profile != "Localhost" &&\n                  !variables.inputAllowedProfiles.exists(profile, profile.type == container.profile)\n              ).map(badProfile, "Seccomp profile \'" + badProfile.profile + "\' is not allowed for container \'" + badProfile.container + "\'. Found at: " + badProfile.location + ". Allowed profiles: " + variables.inputAllowedProfiles.map(profile, "{\\"type\\": \\"" + profile.type + "\\"" + (has(profile.localHostProfile) ? ", \\"localHostProfile\\": \\"" + profile.localHostProfile + "\\"}" : "}")).join(", "))\n          - name: badContainerProfilesWithFiles\n            expression: |\n              variables.allContainerProfiles.filter(container, \n                container.profile == "Localhost" &&\n                !variables.inputAllowedProfiles.exists(profile, profile.type == "Localhost" && (has(profile.localHostProfile) && (profile.localHostProfile == container.file || profile.localHostProfile == "*")))\n              ).map(badProfile, "Seccomp profile \'" + badProfile.profile + "\' With file \'" + badProfile.file + "\' is not allowed for container \'" + badProfile.container + "\'. Found at: " + badProfile.location + ". Allowed profiles: " + variables.inputAllowedProfiles.map(profile, "{\\"type\\": \\"" + profile.type + "\\"" + (has(profile.localHostProfile) ? ", \\"localHostProfile\\": \\"" + profile.localHostProfile + "\\"}" : "}")).join(", "))\n          validations:\n          - expression: \'size(variables.badContainerProfilesWithoutFiles) == 0\'\n            messageExpression: |\n              variables.badContainerProfilesWithoutFiles.join(", ")\n          - expression: \'size(variables.badContainerProfilesWithFiles) == 0\'\n            messageExpression: |\n              variables.badContainerProfilesWithFiles.join(", ")\n      - engine: Rego\n        source:\n          rego: |\n            package k8spspseccomp\n\n            import data.lib.exempt_container.is_exempt\n\n            violation[{"msg": msg}] {\n                not input_wildcard_allowed_profiles\n                allowed_profiles := get_allowed_profiles\n                container := input_containers[name]\n                not is_exempt(container)\n                result := get_profile(container)\n                not allowed_profile(result.profile, result.file, allowed_profiles)\n                msg := get_message(result.profile, result.file, name, result.location, allowed_profiles)\n            }\n\n            get_message(profile, _, name, location, allowed_profiles) = message {\n                profile != "Localhost"\n                message := sprintf("Seccomp profile \'%v\' is not allowed for container \'%v\'. Found at: %v. Allowed profiles: %v", [profile, name, location, allowed_profiles])\n            }\n\n            get_message(profile, file, name, location, allowed_profiles) = message {\n                profile == "Localhost"\n                message := sprintf("Seccomp profile \'%v\' with file \'%v\' is not allowed for container \'%v\'. Found at: %v. Allowed profiles: %v", [profile, file, name, location, allowed_profiles])\n            }\n\n            input_wildcard_allowed_profiles {\n                input.parameters.allowedProfiles[_] == "*"\n            }\n\n            input_wildcard_allowed_files {\n                input.parameters.allowedLocalhostFiles[_] == "*"\n            }\n\n            allowed_profile(_, _, _) {\n                input_wildcard_allowed_profiles\n            }\n\n            allowed_profile(profile, _, _) {\n                profile == "Localhost"\n                input_wildcard_allowed_files\n            }\n\n            # Simple allowed Profiles\n            allowed_profile(profile, _, allowed) {\n                profile != "Localhost"\n                allow_profile = allowed[_]\n                profile == allow_profile.type\n            }\n\n            # annotation localhost without wildcard\n            allowed_profile(profile, file, allowed) {\n                profile == "Localhost"\n                allow_profile = allowed[_]\n                allow_profile.type == "Localhost"\n                file == allow_profile.localHostProfile\n            }\n\n            # The profiles explicitly in the list\n            get_allowed_profiles[allowed] {\n                profile := input.parameters.allowedProfiles[_]\n                profile != "Localhost"\n                allowed := {"type": profile}\n            }\n\n            get_allowed_profiles[allowed] {\n                profile := input.parameters.allowedProfiles[_]\n                profile == "Localhost"\n                file := object.get(input.parameters, "allowedLocalhostFiles", [""])[_]\n                allowed := {"type": "Localhost", "localHostProfile": file}\n            }\n\n            # Container profile as defined in containers securityContext\n            get_profile(container) = {"profile": profile, "file": file, "location": location} {\n                has_securitycontext_container(container)\n                profile := container.securityContext.seccompProfile.type\n                file := object.get(container.securityContext.seccompProfile, "localhostProfile", "")\n                location := "container securityContext"\n            }\n\n            # Container profile as defined in pods securityContext\n            get_profile(container) = {"profile": profile, "file": file, "location": location} {\n                not has_securitycontext_container(container)\n                profile := input.review.object.spec.securityContext.seccompProfile.type\n                file := object.get(input.review.object.spec.securityContext.seccompProfile, "localhostProfile", "")\n                location := "pod securityContext"\n            }\n\n            # Container profile missing\n            get_profile(container) = {"profile": "not configured", "file": "", "location": "no explicit profile found"} {\n                not has_securitycontext_container(container)\n                not has_securitycontext_pod\n            }\n\n            has_securitycontext_pod {\n                input.review.object.spec.securityContext.seccompProfile\n            }\n\n            has_securitycontext_container(container) {\n                container.securityContext.seccompProfile\n            }\n\n            input_containers[container.name] = container {\n                container := input.review.object.spec.containers[_]\n            }\n\n            input_containers[container.name] = container {\n                container := input.review.object.spec.initContainers[_]\n            }\n\n            input_containers[container.name] = container {\n                container := input.review.object.spec.ephemeralContainers[_]\n            }\n          libs:\n            - |\n              package lib.exempt_container\n\n              is_exempt(container) {\n                  exempt_images := object.get(object.get(input, "parameters", {}), "exemptImages", [])\n                  img := container.image\n                  exemption := exempt_images[_]\n                  _matches_exemption(img, exemption)\n              }\n\n              _matches_exemption(img, exemption) {\n                  not endswith(exemption, "*")\n                  exemption == img\n              }\n\n              _matches_exemption(img, exemption) {\n                  endswith(exemption, "*")\n                  prefix := trim_suffix(exemption, "*")\n                  startswith(img, prefix)\n              }\n\n'})}),"\n",(0,o.jsx)(n.h3,{id:"usage",children:"Usage"}),"\n",(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/template.yaml\n"})}),"\n",(0,o.jsx)(n.h2,{id:"examples",children:"Examples"}),"\n",(0,o.jsxs)(i,{children:[(0,o.jsx)("summary",{children:"default-seccomp-required"}),(0,o.jsxs)(i,{children:[(0,o.jsx)("summary",{children:"constraint"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-yaml",children:'apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sPSPSeccompV2\nmetadata:\n  name: psp-seccomp\nspec:\n  match:\n    kinds:\n      - apiGroups: [""]\n        kinds: ["Pod"]\n  parameters:\n    exemptImages:\n    - nginx-exempt \n    allowedProfiles:\n    - RuntimeDefault\n    - Localhost\n    allowedLocalhostFiles:\n    - "*"\n\n'})}),(0,o.jsx)(n.p,{children:"Usage"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/constraint.yaml\n"})})]}),(0,o.jsxs)(i,{children:[(0,o.jsx)("summary",{children:"example-disallowed-global"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-seccomp-disallowed2\n  labels:\n    app: nginx-seccomp\nspec:\n  securityContext:\n    seccompProfile:\n      type: Unconfined\n  containers:\n  - name: nginx\n    image: nginx\n\n"})}),(0,o.jsx)(n.p,{children:"Usage"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/example_disallowed2.yaml\n"})})]}),(0,o.jsxs)(i,{children:[(0,o.jsx)("summary",{children:"example-disallowed-container"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-seccomp-disallowed\n  labels:\n    app: nginx-seccomp\nspec:\n  containers:\n  - name: nginx\n    image: nginx\n    securityContext:\n      seccompProfile:\n        type: Unconfined\n\n"})}),(0,o.jsx)(n.p,{children:"Usage"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/example_disallowed.yaml\n"})})]}),(0,o.jsxs)(i,{children:[(0,o.jsx)("summary",{children:"example-allowed-container"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-seccomp-allowed\n  labels:\n    app: nginx-seccomp\nspec:\n  containers:\n  - name: nginx\n    image: nginx\n    securityContext:\n      seccompProfile:\n        type: RuntimeDefault\n\n"})}),(0,o.jsx)(n.p,{children:"Usage"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/example_allowed.yaml\n"})})]}),(0,o.jsxs)(i,{children:[(0,o.jsx)("summary",{children:"example-allowed-container"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-seccomp-allowed-localhost\n  labels:\n    app: nginx-seccomp\nspec:\n  containers:\n  - name: nginx\n    image: nginx\n    securityContext:\n      seccompProfile:\n        type: Localhost\n        localhostProfile: profile.json\n\n"})}),(0,o.jsx)(n.p,{children:"Usage"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/example_allowed_localhost.yaml\n"})})]}),(0,o.jsxs)(i,{children:[(0,o.jsx)("summary",{children:"example-allowed-container-exempt-image"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-seccomp-disallowed\n  labels:\n    app: nginx-seccomp\nspec:\n  containers:\n  - name: nginx\n    image: nginx-exempt\n    securityContext:\n      seccompProfile:\n        type: Unconfined\n\n"})}),(0,o.jsx)(n.p,{children:"Usage"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/example_allowed_exempt_image.yaml\n"})})]}),(0,o.jsxs)(i,{children:[(0,o.jsx)("summary",{children:"disallowed-ephemeral"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-yaml",children:"apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx-seccomp-disallowed\n  labels:\n    app: nginx-seccomp\nspec:\n  ephemeralContainers:\n  - name: nginx\n    image: nginx\n\n"})}),(0,o.jsx)(n.p,{children:"Usage"}),(0,o.jsx)(n.pre,{children:(0,o.jsx)(n.code,{className:"language-shell",children:"kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/seccompv2/samples/psp-seccomp/disallowed_ephemeral.yaml\n"})})]})]})]})}function m(e={}){const{wrapper:n}={...(0,a.a)(),...e.components};return n?(0,o.jsx)(n,{...e,children:(0,o.jsx)(p,{...e})}):p(e)}},1151:(e,n,i)=>{i.d(n,{Z:()=>s,a:()=>l});var o=i(7294);const a={},t=o.createContext(a);function l(e){const n=o.useContext(t);return o.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function s(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(a):e.components||a:l(e.components),o.createElement(t.Provider,{value:n},e.children)}}}]);