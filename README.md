# OPA Gatekeeper Library

A community-owned library of policies for the OPA Gatekeeper project.

## Usage

Apply the `constraint.yaml` and `template.yaml` provided in each directory under `library/`

```bash
cd library/general/httpsonly/
kubectl apply -f template.yaml
kubectl apply -f samples/ingress-https-only/constraint.yaml
kubectl apply -f library/general/httpsonly/sync.yaml # optional: when GK is running with OPA cache
```
