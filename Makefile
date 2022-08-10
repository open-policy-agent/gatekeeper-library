docker := docker #You can build with podman by doing: make docker=podman
KIND_VERSION ?= 0.14.0
# note: k8s version pinned since KIND image availability lags k8s releases
KUBERNETES_VERSION ?= 1.24.0
KUSTOMIZE_VERSION ?= 4.5.5
GATEKEEPER_VERSION ?= release-3.8
BATS_VERSION ?= 1.3.0
GATOR_VERSION ?= 3.9.0
GOMPLATE_VERSION ?= 3.10.0

integration-bootstrap:
	# Download and install kind
	curl -L https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-amd64 --output ${GITHUB_WORKSPACE}/bin/kind && chmod +x ${GITHUB_WORKSPACE}/bin/kind
	# Download and install kubectl
	curl -L https://storage.googleapis.com/kubernetes-release/release/v${KUBERNETES_VERSION}/bin/linux/amd64/kubectl -o ${GITHUB_WORKSPACE}/bin/kubectl && chmod +x ${GITHUB_WORKSPACE}/bin/kubectl
	# Download and install kustomize
	curl -L https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz -o kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz && tar -zxvf kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz && chmod +x kustomize && mv kustomize ${GITHUB_WORKSPACE}/bin/kustomize
	# Download and install bats
	curl -sSLO https://github.com/bats-core/bats-core/archive/v${BATS_VERSION}.tar.gz && tar -zxvf v${BATS_VERSION}.tar.gz && bash bats-core-${BATS_VERSION}/install.sh ${GITHUB_WORKSPACE}
	# Download and install yq
	sudo snap install yq
	# Check for existing kind cluster
	if [ $$(${GITHUB_WORKSPACE}/bin/kind get clusters) ]; then ${GITHUB_WORKSPACE}/bin/kind delete cluster; fi
	# Create a new kind cluster
	TERM=dumb ${GITHUB_WORKSPACE}/bin/kind create cluster --image kindest/node:v${KUBERNETES_VERSION} --wait 5m --config=test/kind_config.yaml

deploy:
	kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${GATEKEEPER_VERSION}/deploy/gatekeeper.yaml

uninstall:
	kubectl delete -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${GATEKEEPER_VERSION}/deploy/gatekeeper.yaml

test-integration:
	bats -t test/bats/test.bats

.PHONY: verify-gator
verify-gator:
	gator verify ./...

.PHONY: verify-gator-dockerized
verify-gator-dockerized: __build-gator
	$(docker) run -i -v $(shell pwd):/gatekeeper-library gator-container verify ./...

.PHONY: build-gator
__build-gator:
	$(docker) build --build-arg GATOR_VERSION=$(GATOR_VERSION) -f build/gator/Dockerfile -t gator-container .

.PHONY: generate
generate: __build-gomplate
	$(docker) run -v $(shell pwd):/gatekeeper-library gomplate-container ./scripts/generate.sh

.PHONY: __build-gomplate
__build-gomplate:
	$(docker) build --build-arg GOMPLATE_VERSION=$(GOMPLATE_VERSION) -f build/gomplate/Dockerfile -t gomplate-container .

.PHONY: require-suites
require-suites:
	./scripts/require-suites.sh
