KIND_VERSION ?= 0.8.1
# note: k8s version pinned since KIND image availability lags k8s releases
KUBERNETES_VERSION ?= v1.19.0
KUSTOMIZE_VERSION ?= 3.7.0
GATEKEEPER_VERSION ?= release-3.1

integration-bootstrap:
	# Download and install kind
	curl -L https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-amd64 --output ${GITHUB_WORKSPACE}/bin/kind && chmod +x ${GITHUB_WORKSPACE}/bin/kind
	# Download and install kubectl
	curl -L https://storage.googleapis.com/kubernetes-release/release/${KUBERNETES_VERSION}/bin/linux/amd64/kubectl -o ${GITHUB_WORKSPACE}/bin/kubectl && chmod +x ${GITHUB_WORKSPACE}/bin/kubectl
	# Download and install kustomize
	curl -L https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz -o kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz && tar -zxvf kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz && chmod +x kustomize && mv kustomize ${GITHUB_WORKSPACE}/bin/kustomize
	# Download and install bats
	sudo apt-get -o Acquire::Retries=30 update && sudo apt-get -o Acquire::Retries=30 install -y bats
	# Download and install yq
	sudo snap install yq
	# Check for existing kind cluster
	if [ $$(kind get clusters) ]; then kind delete cluster; fi
	# Create a new kind cluster
	TERM=dumb kind create cluster --image kindest/node:${KUBERNETES_VERSION} --config=test/kind_config.yaml

deploy:
	kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${GATEKEEPER_VERSION}/deploy/gatekeeper.yaml

uninstall:
	kubectl delete -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${GATEKEEPER_VERSION}/deploy/gatekeeper.yaml

test-integration:
	bats -t test/bats/test.bats
