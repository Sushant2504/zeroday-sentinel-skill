# CI/CD Pipeline Security Reference

Security checks for GitHub Actions, CI/CD workflows, and build pipeline configurations.

## GitHub Actions Security

### Workflow Permissions

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Overly broad permissions | `permissions: write-all` or no `permissions` key (defaults to broad) | HIGH | Set `permissions: read-all` at workflow level. Grant write permissions per-job only where needed |
| Unnecessary write scopes | `contents: write`, `packages: write` when only reads are needed | MEDIUM | Audit each job's needs. Remove write scopes not actively used. Use `contents: read` as default |
| Missing permissions block | Workflow without explicit `permissions` declaration | MEDIUM | Add explicit `permissions:` block at workflow level. Start with `read-all` and add writes as needed |

**Best practice:**
```yaml
# Top of workflow
permissions: read-all

jobs:
  build:
    permissions:
      contents: read
  deploy:
    permissions:
      contents: read
      deployments: write
```

### Action Pinning

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unpinned actions | `uses: actions/checkout@v4` (tag, not SHA) | MEDIUM | Pin to SHA: `uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11`. Use `pinact` tool to auto-pin |
| Branch references | `uses: org/action@main` | HIGH | Pin to SHA. Branch refs can be moved by anyone with write access to the action repo |
| Latest tag | `uses: org/action@latest` | HIGH | Pin to specific SHA. Use Dependabot/Renovate to keep pins updated |

**Remediation — Auto-pin actions:**
```bash
# Install pinact
npm install -g pinact

# Pin all actions in a workflow
pinact .github/workflows/*.yml

# Set up Dependabot for action updates
# .github/dependabot.yml:
# updates:
#   - package-ecosystem: github-actions
#     directory: /
#     schedule:
#       interval: weekly
```

### Dangerous Triggers

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| `pull_request_target` | Trigger that runs with repo write access on PR code | CRITICAL | Use `pull_request` trigger instead. If `pull_request_target` is needed, never check out PR code in the same job |
| `pull_request_target` + `checkout PR` | Checking out PR head ref in `pull_request_target` workflow | CRITICAL | Split into two workflows: one `pull_request_target` (labels only), one `pull_request` (builds/tests) |
| `workflow_dispatch` without auth | Manual trigger without required approvals | MEDIUM | Use GitHub Environments with required reviewers for manual deployments |
| `repository_dispatch` | External event trigger — verify source authentication | MEDIUM | Validate `client_payload` contents. Restrict which external services can trigger |

**Why `pull_request_target` is dangerous:** It runs with the base repo's secrets and write permissions but can be triggered by untrusted PR code. If the workflow checks out the PR's code, an attacker's code runs with elevated privileges.

**Safe pattern:**
```yaml
# SAFE: pull_request_target that never checks out PR code
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/labeler@v5  # only labels, no checkout
```

### Secret Handling

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Secrets in run commands | `echo ${{ secrets.* }}` or printing secrets in logs | CRITICAL | Never echo secrets. Use `::add-mask::` if a secret must be in output. Access secrets only in the step that needs them |
| Secrets as env for all steps | `env: SECRET: ${{ secrets.* }}` at job level when only one step needs it | MEDIUM | Move secret to step-level `env:` block. Minimizes exposure surface |
| Secrets in outputs | `echo "::set-output name=val::${{ secrets.* }}"` | CRITICAL | Never put secrets in outputs. Use intermediate files or environment variables scoped to the step |
| Secrets in artifact uploads | Uploading files that contain injected secrets | HIGH | Scrub secrets from artifacts before upload. Don't inject secrets into build output |
| Missing environment protection | Secrets not scoped to GitHub Environments with approval rules | MEDIUM | Create Environments (staging, production) with required reviewers and deployment branch rules |

### Script Injection

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Direct context interpolation | `run: echo "${{ github.event.issue.title }}"` | HIGH | Pass through env var: `env: TITLE: ${{ github.event.issue.title }}` then `run: echo "$TITLE"` |
| PR title/body in commands | Using `${{ github.event.pull_request.title }}` in `run:` | HIGH | Same pattern — assign to env var first, then use shell-quoted `"$VAR"` |
| Comment body in commands | Using `${{ github.event.comment.body }}` in `run:` | CRITICAL | Comments are fully attacker-controlled. Always pass through env var. Consider validating format before use |

**Remediation — Safe pattern for user-controlled context:**
```yaml
- name: Process PR
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
    PR_BODY: ${{ github.event.pull_request.body }}
  run: |
    echo "Title: $PR_TITLE"
    echo "Body: $PR_BODY"
```

**Prevention — actionlint setup:**
```bash
# Install actionlint
go install github.com/rhysd/actionlint/cmd/actionlint@latest

# Run on all workflows
actionlint .github/workflows/*.yml

# Add to CI
# - name: Lint GitHub Actions
#   uses: reviewdog/action-actionlint@v1
```

### Self-Hosted Runner Risks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Self-hosted on public repos | `runs-on: self-hosted` in public repository | CRITICAL | Use GitHub-hosted runners for public repos. If self-hosted required, use ephemeral runners (Actions Runner Controller) |
| Persistent self-hosted runners | Self-hosted without ephemeral configuration | HIGH | Configure runners as ephemeral: `--ephemeral` flag. Use Actions Runner Controller with scale-to-zero |
| Missing runner labels | Using `self-hosted` without environment-specific labels | MEDIUM | Use labels: `runs-on: [self-hosted, linux, production]`. Separate runners by environment |

## General CI/CD Patterns

### Build Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Skip verification flags | `--no-verify`, `--skip-tests`, `--no-check` in build scripts | HIGH | Remove skip flags. Fix the underlying test/check failures. If temporarily needed, create a tracked issue |
| Disabled security scans | Conditional skips of security scanning steps | HIGH | Make security scans required. Don't allow `if: false` or skip conditions on security steps |
| Unvalidated external inputs | Build scripts using environment variables without validation | MEDIUM | Validate all external inputs in build scripts. Use strict mode (`set -euo pipefail`) |
| Missing build reproducibility | No pinned tool versions in build environment | MEDIUM | Pin all tool versions: `uses: actions/setup-node@v4 with: node-version: '20.11.0'` |

### Credential Leakage

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Credentials in CLI args | `--password`, `--token`, `--api-key` with values (visible in process list) | HIGH | Use stdin: `echo "$TOKEN" \| cmd --token-stdin`. Use environment variables |
| Credentials in logs | `set -x` in scripts that handle credentials | HIGH | Use `set +x` before credential operations, `set -x` after. Or use `{ set +x; } 2>/dev/null` |
| Unmasked outputs | Credential values not wrapped in `::add-mask::` | MEDIUM | Add `echo "::add-mask::$SECRET"` before any step that might log the value |
| Credentials in build cache | Docker build cache containing credential layers | HIGH | Use BuildKit secrets: `RUN --mount=type=secret`. Use multi-stage builds where secret layers are discarded |

### Supply Chain Integrity

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No integrity checks | Downloading binaries/dependencies without checksum verification | HIGH | Verify checksums: `sha256sum -c checksums.txt`. Use package manager lock files |
| HTTP downloads | `curl http://` or `wget http://` (not HTTPS) | HIGH | Always use HTTPS. Verify TLS certificate. Add `--fail` flag to curl |
| Missing SLSA provenance | Release artifacts without provenance attestation | LOW | Use SLSA GitHub generator: `slsa-framework/slsa-github-generator`. Add provenance to releases |
| Unsigned containers | Publishing container images without signing (cosign/notation) | MEDIUM | Sign images with cosign: `cosign sign --key cosign.key image:tag`. Verify in admission controller |

## Tekton Pipeline Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Privileged tasks | `securityContext.privileged: true` in task steps | HIGH | Remove privileged mode. Use Kaniko or Buildah for container builds without Docker socket |
| Unbounded resources | Tasks without resource limits | MEDIUM | Add resource limits to all task steps: `resources: { limits: { memory: "1Gi", cpu: "1" } }` |
| Inline scripts with secrets | Secret references in inline script blocks | HIGH | Use Tekton Secrets with volume mounts. Never inline secret values in task definitions |
| Missing pipeline-level RBAC | ServiceAccount with excessive cluster permissions | HIGH | Create pipeline-specific ServiceAccount with minimum ClusterRole/Role bindings |

## Jenkins Pipeline Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Plaintext credentials | `withCredentials` blocks logging credential values | HIGH | Never echo credentials. Use `credentials()` binding with `usernamePassword` or `string` type |
| Groovy sandbox bypass | `@NonCPS` annotations or script approval bypasses | HIGH | Minimize `@NonCPS` usage. Review all script approvals. Use declarative pipeline instead of scripted |
| Shared library trust | Loading shared libraries from untrusted sources | HIGH | Pin shared libraries to specific versions/commits. Only load from trusted internal repos |
| Agent label wildcards | `agent any` in production pipelines | MEDIUM | Use specific agent labels: `agent { label 'linux && production' }`. Separate agents by environment |
