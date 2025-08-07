# Agent Instructions for OPA Gatekeeper Library

## Project Overview
**OPA Gatekeeper Library** is a community-owned library of policies for the [OPA Gatekeeper project](https://open-policy-agent.github.io/gatekeeper/website/docs/). This repository contains **validation** and **mutation** policies implemented as Kubernetes Custom Resource Definitions (ConstraintTemplates and Constraints) that integrate with the OPA Gatekeeper admission controller.

**Repository Size & Structure:**
- **Large repository** (~50+ validation policies, ~6 mutation policies)
- **Languages:** Rego (policy logic), Go (tooling/scripts), YAML (Kubernetes manifests), Gomplate (templating), **CEL (Common Expression Language for K8sNativeValidation)**
- **Key Technologies:** Open Policy Agent (OPA), Kubernetes CRDs, Gatekeeper, Docker, Helm, **CEL (K8sNativeValidation engine)**
- **Architecture:** Template-driven code generation from `src/` to `library/` using gomplate
- **Policy Engines:** **Dual-engine support** - policies can have both Rego (OPA) and CEL (K8sNativeValidation) implementations

## Critical Build & Validation Commands

### Environment Prerequisites
**Always ensure these tools are available before development:**
- **Docker**: Required for all generation and testing (containerized tools)
- **Go 1.20+**: Required for script validation and tooling
- **gator CLI**: Required for policy testing (install from [Gatekeeper releases](https://github.com/open-policy-agent/gatekeeper/releases))
- **OPA CLI**: Required for Rego unit tests (install from [OPA releases](https://github.com/open-policy-agent/opa/releases))

### Essential Build Commands (Must Work Before PR)
**CRITICAL: Always run these commands in this exact order before submitting any changes:**

1. **Generate library manifests** (REQUIRED for every src/ change):
   ```bash
   make generate
   ```
   - Generates `library/*/template.yaml` from `src/*/constraint.tmpl`
   - Uses dockerized gomplate - will build container if needed
   - **Always run this after editing any file in src/**

2. **Validate repository structure** (REQUIRED):
   ```bash
   make validate
   ```
   - Validates website docs directory structure
   - Runs in ~1 second

3. **Run Go unit tests for scripts** (REQUIRED):
   ```bash
   make unit-test
   ```
   - Tests all Go tooling in scripts/artifacthub, scripts/validate, scripts/require-sync
   - Runs in ~1-2 seconds

4. **Validate sync requirements** (REQUIRED):
   ```bash
   make require-sync
   ```
   - Validates that policies using data.inventory have proper sync.yaml files
   - Validates metadata.gatekeeper.sh/requires-sync-data annotations
   - Runs in ~2-3 seconds

5. **Validate suite.yaml files exist** (REQUIRED):
   ```bash
   make require-suites
   ```
   - Ensures every template.yaml has a corresponding suite.yaml test file
   - Runs in ~1 second

6. **Run OPA unit tests** (REQUIRED - needs OPA CLI):
   ```bash
   ./test.sh
   ```
   - Runs `opa test` on all Rego files in strict mode
   - **Will fail with "opa: command not found" if OPA CLI not installed**
   - Install OPA: `curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/v0.57.1/opa_linux_amd64 && chmod +x opa && sudo mv opa /usr/local/bin/`

7. **Run gator integration tests** (REQUIRED - needs gator CLI):
   ```bash
   make verify-gator-dockerized POLICY_ENGINE=rego
   ```
   - Tests all suite.yaml files using dockerized gator
   - **Will fail if gator CLI not available**
   - For CEL policies: `make verify-gator-dockerized POLICY_ENGINE=cel`

### Complete CI Validation Sequence
**To replicate exactly what CI does:**
```bash
# Generate and validate everything is up-to-date
make generate generate-website-docs generate-artifacthub-artifacts
git diff --exit-code || (echo "Files need regeneration" && exit 1)

# Run all validation checks
make validate
make unit-test  
make require-suites
make require-sync

# Run policy tests (requires OPA and gator CLI)
./test.sh
make verify-gator-dockerized POLICY_ENGINE=rego
make verify-gator-dockerized POLICY_ENGINE=cel
```

## Project Structure & Architecture

### Repository Layout
```
├── src/                                     # Source templates and Rego/CEL policies (EDIT HERE)
│   ├── general/                             # General validation policies  
│   │   ├── httpsonly/                       # Example: HTTPS-only ingress policy (Rego only)
│   │   │   ├── constraint.tmpl              # Gomplate template → generates library/.../template.yaml
│   │   │   ├── src.rego                     # Rego policy logic
│   │   │   └── src_test.rego                # OPA unit tests
│   │   ├── requiredlabels/                  # Example: Required labels policy (Rego + CEL)
│   │   │   ├── constraint.tmpl              # Dual-engine template (both Rego and CEL)
│   │   │   ├── src.rego                     # Rego policy logic
│   │   │   ├── src.cel                      # CEL policy logic (K8sNativeValidation engine)
│   │   │   └── src_test.rego                # OPA unit tests (CEL tested via gator)
│   │   └── [policy-name]/                   # Pattern for all policies
│   ├── pod-security-policy/                 # Pod Security Policy equivalent validations (mostly Rego + CEL)
│   └── rego/                                # Shared Rego utilities
├── library/                                 # Generated Kubernetes manifests (DO NOT EDIT)
│   ├── general/                             # Generated validation templates
│   │   ├── httpsonly/                       # Generated from src/general/httpsonly/
│   │   │   ├── template.yaml                # Generated ConstraintTemplate (AUTO-GENERATED)
│   │   │   ├── kustomization.yaml           # Kustomize config (MANUALLY MAINTAINED)
│   │   │   ├── suite.yaml                   # Gator test cases (MANUALLY MAINTAINED)  
│   │   │   ├── sync.yaml                    # Optional: OPA data sync config
│   │   │   └── samples/                     # Example constraints and test resources
│   │   │       └── [constraint-name]/       # Sample constraint + test resources
│   │   └── [policy-name]/                   # Pattern for all generated policies
│   └── pod-security-policy/                 # Generated PSP-equivalent templates
├── mutation/                                # Mutation policy examples (manually maintained)
│   └── pod-security-policy/                 # Example mutation policies
├── scripts/                                 # Go tooling and automation
│   ├── generate.sh                          # Main template generation script
│   ├── require-suites.sh                    # Validates suite.yaml files exist
│   ├── artifacthub/                         # Go: ArtifactHub package generation
│   ├── validate/                            # Go: Repository structure validation
│   ├── require-sync/                        # Go: Sync requirements validation
│   └── website/                             # Go: Website documentation generation
├── build/                                   # Docker build contexts
│   ├── gomplate/Dockerfile                  # Container for template generation
│   └── gator/Dockerfile                     # Container for policy testing
├── test/                                    # Integration test configurations
│   ├── kind_config.yaml                     # Kind cluster configuration
│   └── bats/                                # BATS integration tests
├── .github/workflows/                       # CI/CD pipelines
│   ├── workflow.yaml                        # Main CI pipeline (tests on rego/cel + multiple gatekeeper versions)
│   ├── website.yaml                         # Website deployment
│   └── scripts.yaml                         # Script validation
├── artifacthub/                             # Generated ArtifactHub packages
├── website/                                 # Generated documentation website
├── go.work                                  # Go workspace for scripts
├── .golangci.yaml                           # Go linting configuration  
├── Makefile                                 # Main build commands
└── test.sh                                  # OPA unit test runner
```

## Policy Development Workflow

### Adding a New Validation Policy
**Required structure for every new policy:**

1. **Create source files** in `src/[category]/[policy-name]/`:
   ```bash
   mkdir -p src/general/my-new-policy
   # Create these required files:
   # constraint.tmpl - Gomplate template with CRD definition (supports both Rego and CEL engines)
   # src.rego - Rego policy logic  
   # src_test.rego - OPA unit tests
   # src.cel - OPTIONAL: CEL policy logic for K8sNativeValidation engine
   ```

2. **Create library structure** in `library/[category]/[policy-name]/`:
   ```bash
   mkdir -p library/general/my-new-policy/samples/my-constraint-example
   # Create these required files:
   # kustomization.yaml - Kustomize configuration
   # suite.yaml - Gator test cases (tests both Rego and CEL if present)
   # samples/[name]/ - Example constraints and test resources
   # sync.yaml - ONLY if policy uses data.inventory
   ```

3. **Generate and test**:
   ```bash
   make generate                    # Generate template.yaml
   make validate                    # Validate structure
   ./test.sh                       # Run OPA unit tests (Rego only)
   make verify-gator-dockerized POLICY_ENGINE=rego  # Test Rego engine
   make verify-gator-dockerized POLICY_ENGINE=cel   # Test CEL engine (if src.cel exists)
   ```

**IMPORTANT: Always add CEL (src.cel) for new policies unless they use referential data or external data sources.**

### Dual-Engine Policy Development (Rego + CEL)
**Many policies support both engines for maximum compatibility:**

**CRITICAL: For new policies, always implement CEL alongside Rego unless the policy:**
- Uses referential data (`data.inventory`)
- Requires external data sources
- Has a `sync.yaml` file requirement
- Contains complex logic that cannot be expressed in CEL

**constraint.tmpl structure for dual-engine policies:**
```yaml
spec:
  targets:
    - target: admission.k8s.gatekeeper.sh
      code:
      - engine: K8sNativeValidation          # CEL engine (Kubernetes native)
        source:
{{ file.Read "src/[category]/[policy-name]/src.cel" | strings.Indent 10 | strings.TrimSuffix "\n" }}
      - engine: Rego                         # OPA engine (traditional)
        source:
          rego: |
{{ file.Read "src/[category]/[policy-name]/src.rego" | strings.Indent 12 | strings.TrimSuffix "\n" }}
```

**CEL Policy Structure (src.cel):**
```cel
# CEL uses variables and validations blocks
variables:
- name: variableName
  expression: |
    # CEL expression to compute variable
validations:
- expression: '# CEL boolean expression that must be true'
  messageExpression: '"Error message: " + variable'  # Dynamic error message
- expression: '# Additional validation rule'
  message: "Static error message"                     # Static error message
```

**CEL vs Rego Patterns:**
- **CEL**: More performant, Kubernetes-native, simpler syntax for basic validations
- **Rego**: More powerful for complex logic, better testing support, established ecosystem
- **Use both**: Provides fallback compatibility and allows users to choose their preferred engine

### Policy Version Requirements
**MANDATORY: Add version annotations to constraint.tmpl:**
```yaml
metadata:
  annotations:
    metadata.gatekeeper.sh/version: "1.0.0"  # REQUIRED: Semantic versioning
```

**Version bump rules:**
- **Major**: Breaking changes (schema changes, new sync requirements)
- **Minor**: Backward-compatible additions (new parameters, logic updates)
- **Patch**: Simple fixes (bug fixes, metadata updates)

### Testing Patterns
**Unit Testing (Rego only - CEL tested via gator):**
```bash
# Test specific policy (Rego unit tests)
opa test src/general/httpsonly/*.rego --verbose

# Debug Rego with trace
# Add to Rego: trace(sprintf("Debug: %v", [variable]))
```

**Integration Testing (Gator - tests both engines):**
```bash
# Test specific policy (tests both Rego and CEL if present)
gator verify library/general/requiredlabels/

# Test all policies with Rego engine
gator verify ./... --enable-k8s-native-validation=false

# Test all policies with CEL engine (K8sNativeValidation)
gator verify ./... --enable-k8s-native-validation=true

# Use Makefile targets for dockerized testing
make verify-gator-dockerized POLICY_ENGINE=rego  # Tests Rego implementations
make verify-gator-dockerized POLICY_ENGINE=cel   # Tests CEL implementations
```

**CEL Development Notes:**
- **No unit testing framework** for CEL - rely on gator integration tests in suite.yaml
- **CEL expressions** are Kubernetes-native and more performant than Rego
- **Error messages** can be dynamic using `messageExpression` or static using `message`
- **Variables** in CEL help break down complex expressions for readability
- **Testing**: gator automatically tests CEL when `--enable-k8s-native-validation=true`

## Key Configuration Files

- **Makefile**: All build targets, version configurations, tool versions, **POLICY_ENGINE variable (valid values: 'rego', 'cel') for rego/cel testing**
- **.golangci.yaml**: Go linting rules for scripts (Go 1.20, strict rules)
- **go.work**: Go workspace for scripts (artifacthub, validate, require-sync, website)
- **test/kind_config.yaml**: Kubernetes cluster config for integration tests
- **.github/workflows/workflow.yaml**: Main CI pipeline (tests both rego/cel engines on two latest Gatekeeper versions)

## Policy Engine Selection & Testing

**The library supports both policy engines:**
- **Rego (OPA)**: Traditional engine, more mature tooling, comprehensive unit testing
- **CEL (K8sNativeValidation)**: Kubernetes-native, higher performance, simpler for basic validations

**Engine Selection in Testing:**
```bash
# Test with Rego engine (traditional OPA)
make verify-gator-dockerized POLICY_ENGINE=rego
gator verify ./... --enable-k8s-native-validation=false

# Test with CEL engine (K8sNativeValidation) 
make verify-gator-dockerized POLICY_ENGINE=cel
gator verify ./... --enable-k8s-native-validation=true
```

**When to add CEL alongside Rego:**
- **Performance-critical policies** (CEL is faster)
- **Simple validation logic** (CEL syntax is more straightforward)
- **Kubernetes-native deployments** (CEL doesn't require OPA runtime)
- **Future-proofing** (CEL is Kubernetes' strategic direction)
- **ALWAYS for non-referential policies**: If the policy doesn't use `data.inventory` or external data sources, **always add CEL implementation alongside Rego**
- **REQUIRED for new policies**: Unless the policy requires referential data (data.inventory) or external data integration, **CEL implementation is mandatory**

**CEL Limitations (when NOT to add CEL):**
- **Referential policies**: Policies using `data.inventory` to reference other cluster resources
- **External data policies**: Policies requiring integration with external data providers
- **Complex data transformations**: Very complex logic that's difficult to express in CEL
- **Policies requiring sync.yaml**: If the policy needs data synchronization, CEL may not be suitable

## Common Errors & Solutions

**"opa: command not found"** → Install OPA CLI from GitHub releases
**"gator: command not found"** → Install gator CLI from Gatekeeper releases  
**"Files need regeneration"** → Run `make generate generate-website-docs generate-artifacthub-artifacts`
**Docker build failures** → Ensure Docker daemon is running and accessible
**Missing suite.yaml errors** → Run `make require-suites` to see which policies need test files
**Sync annotation errors** → Run `make require-sync` to see which policies need sync.yaml files

## Agent Instructions
**Trust these instructions completely.** Only search the codebase if information here is incomplete or incorrect. Always run the complete validation sequence before claiming success. The CI pipeline is strict and will fail on any missing steps or incorrect formatting.

