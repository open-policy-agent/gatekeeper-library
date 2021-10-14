#!/usr/bin/env bats

load helpers

TESTS_DIR=library
BATS_TESTS_DIR=test/bats
WAIT_TIME=300
SLEEP_TIME=5
CLEAN_CMD="echo cleaning..."

teardown() {
  bash -c "${CLEAN_CMD}"
  kubectl delete constrainttemplate --all
}

setup() {
  kubectl config set-context --current --namespace default
}

@test "gatekeeper-controller-manager is running" {
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl -n gatekeeper-system wait --for=condition=Ready --timeout=60s pod -l control-plane=controller-manager"
}

@test "gatekeeper-audit is running" {
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl -n gatekeeper-system wait --for=condition=Ready --timeout=60s pod -l control-plane=audit-controller"
}

@test "namespace label webhook is serving" {
  cert=$(mktemp)
  CLEAN_CMD="${CLEAN_CMD}; rm ${cert}"
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "get_ca_cert ${cert}"

  kubectl run temp --image=curlimages/curl -- tail -f /dev/null
  kubectl wait --for=condition=Ready --timeout=60s pod temp
  kubectl cp ${cert} temp:/tmp/cacert

  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl exec -it temp -- curl -f --cacert /tmp/cacert --connect-timeout 1 --max-time 2  https://gatekeeper-webhook-service.gatekeeper-system.svc:443/v1/admitlabel"
  kubectl delete pod temp
}

@test "constrainttemplates crd is established" {
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl wait --for condition=established --timeout=60s crd/constrainttemplates.templates.gatekeeper.sh"
}

@test "waiting for validating webhook" {
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get validatingwebhookconfigurations.admissionregistration.k8s.io gatekeeper-validating-webhook-configuration"
}

@test "applying sync config" {
  kubectl apply -f ${BATS_TESTS_DIR}/sync.yaml
}

@test "waiting for namespaces to be synced using metrics endpoint" {
  kubectl run temp --image=curlimages/curl -- tail -f /dev/null
  kubectl wait --for=condition=Ready --timeout=60s pod temp

  num_namespaces=$(kubectl get ns -o json | jq '.items | length')
  local pod_ip="$(kubectl -n gatekeeper-system get pod -l gatekeeper.sh/operation=webhook -ojson | jq --raw-output '[.items[].status.podIP][0]' | sed 's#\.#-#g')"
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl exec -it temp -- curl http://${pod_ip}.gatekeeper-system.pod:8888/metrics | grep 'gatekeeper_sync{kind=\"Namespace\",status=\"active\"} ${num_namespaces}'"
  kubectl delete pod temp
}

@test "testing constraint templates" {
  for policy in "$TESTS_DIR"/*/*; do
    if [ -d "$policy" ]; then
      local policy_group=$(basename "$(dirname "$policy")")
      local template_name=$(basename "$policy")
      if [[ $policy_group == "experimental"  ]]; then
        continue
      fi
      echo "running integration test against policy group: $policy_group, constraint template: $template_name"
      # apply template
      wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl apply -k $policy"
      local kind=$(yq e .metadata.name "$policy"/template.yaml)
      for sample in "$policy"/samples/*; do
        echo "testing sample constraint: $(basename "$sample")"
        # apply constraint
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl apply -f ${sample}/constraint.yaml"
        local name=$(yq e .metadata.name "$sample"/constraint.yaml )
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "constraint_enforced $kind $name"

        for allowed in "$sample"/example_allowed*.yaml; do
          if [[ -e "$allowed" ]]; then
            # apply resource
            run kubectl apply -f "$allowed"
            assert_match 'created' "$output"
            assert_success
            # delete resource
            kubectl delete --ignore-not-found -f "$allowed"
          fi
        done

        for disallowed in "$sample"/example_disallowed*.yaml; do
          if [[ -e "$disallowed" ]]; then
            # apply resource
            run kubectl apply -f "$disallowed"
            assert_match 'denied the request' "${output}"
            assert_failure
            # delete resource
            kubectl delete --ignore-not-found -f "$disallowed"
          fi
        done
        # delete constraint
        kubectl delete -f "$sample"/constraint.yaml
      done
      # delete template
      kubectl delete -k "$policy"
    fi
  done
}
