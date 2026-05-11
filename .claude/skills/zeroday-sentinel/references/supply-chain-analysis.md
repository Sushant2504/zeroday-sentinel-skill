# Supply Chain Analysis Reference

Detailed procedures for dependency analysis, OpenSSF Scorecard evaluation, and supply chain threat intelligence.

## Dependency Files to Watch

| Ecosystem | Files | Version Pinning Expectation |
|-----------|-------|---------------------------|
| Go | `go.mod`, `go.sum` | Module versions enforced by Go tooling |
| Python | `requirements.txt`, `pyproject.toml`, `uv.lock`, `Pipfile.lock` | Exact pins (`==`) in production requirements |
| Node.js | `package.json`, `package-lock.json`, `yarn.lock` | Exact versions in lock files |
| Terraform | `*.tf` (provider/module `source` blocks), `.terraform.lock.hcl` | Version constraints with lock file |
| Containers | `Dockerfile`, `Containerfile` | Exact image tags or SHA digests |
| Helm | `Chart.yaml` (dependency entries), `Chart.lock` | Pinned chart versions |
| Ruby | `Gemfile`, `Gemfile.lock` | Exact versions in lock file |
| Rust | `Cargo.toml`, `Cargo.lock` | Lock file pinning |

## Tag Pinning Rules

The `:latest` tag and equivalent unpinned version specifiers are **never acceptable**. Flag every occurrence.

| Context | Violation Examples | Expected |
|---------|-------------------|----------|
| Dockerfile `FROM` | `FROM nginx:latest`, `FROM nginx` (implicit latest) | `FROM nginx:1.27.0` or `FROM nginx@sha256:...` |
| Helm `image.tag` | `tag: latest`, `tag: ""` | `tag: "v1.2.3"` |
| Terraform container image | `image = "nginx:latest"` | `image = "nginx:1.27.0"` |
| Kubernetes manifests | `image: nginx:latest` | `image: nginx:1.27.0` |
| Python dependencies | `requests`, `requests>=2.0` | `requests==2.31.0` |
| Node.js dependencies | `"lodash": "*"`, `"lodash": "latest"` | `"lodash": "4.17.21"` |
| GitHub Actions | `uses: actions/checkout@main` | `uses: actions/checkout@sha256hash` |

Report as **MEDIUM** severity under `Infrastructure - Unpinned Image Tag` or `Application - Unpinned Dependency Version`.

## Suspiciously New Package Versions

Newly published package versions (released within the last 7 days) are a supply chain risk.

### How to Check

For each added or updated dependency in the diff:

1. **Determine the publish date** of the specific version:
   - **Go**: WebSearch for `"<module>@<version>"` on pkg.go.dev or the module's release page
   - **Python**: WebSearch for `"<package> <version>"` on pypi.org — check the version history page
   - **Node.js**: WebSearch for `"<package> <version>"` on npmjs.com — check the publish date
   - **Terraform providers/modules**: Check the Terraform Registry or GitHub releases page
   - **Container images**: Check the registry (Docker Hub, quay.io, ECR) for the tag's push date
   - **Helm charts**: Check the chart repository or GitHub releases

2. **Compare against today's date**: If published within the last 7 days, flag it.

3. **Report** as **MEDIUM** under `Supply Chain - Suspiciously New Version` with:
   - The package name and version
   - The publish date
   - A note to hold until more community vetting or verify legitimacy

### What NOT to Do

- Do not flag version bumps to versions older than 7 days
- Do not flag dependencies that were not changed in the diff
- If the publish date cannot be determined, note the uncertainty but do not block

## Bulk Dependency Changes

A diff that changes more than 10 package versions at once is a supply chain risk.

### How to Check

1. **Count changed dependencies**: From the diff, count added, removed, or version-changed entries across all dependency files. Count each package once even if it appears in multiple files.

2. **If count exceeds 10**: Flag as **HIGH** under `Supply Chain - Bulk Dependency Change` with:
   - Total number of dependencies changed
   - Breakdown by ecosystem (e.g., "8 Go modules, 5 Python packages")
   - Recommendation to split into smaller, reviewable chunks

3. **Escalate scrutiny**: When bulk change is detected, apply the Suspiciously New Package Versions check to **every** changed dependency, not just added ones.

### Exceptions

- **Lock file regeneration**: If only lock files changed (`go.sum`, `uv.lock`, `package-lock.json`) and the manifest file has no version changes, report as **LOW** instead of HIGH.
- **Automated tooling**: If PR title/description indicates Dependabot, Renovate, or similar tools, note the context but still flag for review.

## OpenSSF Scorecard Evaluation

For any **newly added** dependency (not version bumps of existing ones), evaluate the upstream repository's security posture.

### When to Run

Only for dependencies that appear **for the first time** in a dependency file. Skip version bumps of existing dependencies.

### How to Query

Before constructing the URL, validate that `{owner}` and `{repo}` values contain only alphanumeric characters, hyphens, underscores, dots, and forward slashes. Reject any values containing spaces, quotes, semicolons, or shell metacharacters.

```bash
curl -s "https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}"
```

### Mapping Packages to Repositories

| Ecosystem | How to Find Source Repo |
|-----------|----------------------|
| Go | Module path starting with `github.com/` maps directly |
| Python | PyPI page `repository` or `homepage` URL |
| Node.js | `repository` field on npm page |
| Terraform | Module `source` block contains GitHub reference |
| Container images | Registry page for source repository link |

If the source repository is not on GitHub or cannot be determined, skip the Scorecard check and note it.

### Interpreting Results

The API returns an aggregate `score` (0-10) and individual `checks`.

**Flag these conditions:**

| Condition | Severity | Category |
|-----------|----------|----------|
| Aggregate score < 3 | **HIGH** | `Supply Chain - Low Scorecard Rating` |
| Aggregate score 3-5 | **MEDIUM** | `Supply Chain - Low Scorecard Rating` |
| `Maintained` check score = 0 | **HIGH** | `Supply Chain - Unmaintained Dependency` |
| `Dangerous-Workflow` check score < 5 | **HIGH** | `Supply Chain - Dangerous Upstream Workflow` |
| `Branch-Protection` check score = 0 | **MEDIUM** | `Supply Chain - Weak Upstream Controls` |
| `Code-Review` check score = 0 | **MEDIUM** | `Supply Chain - Weak Upstream Controls` |
| `Signed-Releases` check score = 0 | **LOW** | `Supply Chain - Unsigned Releases` |

**Include in report:**
- Dependency name and upstream repository
- Aggregate score
- Any checks that triggered a flag, with the check's `reason` field
- Recommendation (e.g., "evaluate alternatives", "pin to verified commit hash", "accept risk with justification")

### What NOT to Do

- Do not block on API failures — note the gap and move on
- Do not flag dependencies with aggregate score >= 6
- Do not run Scorecard on version bumps of existing dependencies

## Threat Intelligence Search

For each added or updated package, search for recent supply chain threats:

### Search Queries

```
"<package-name>" supply chain attack
"<package-name>" malware compromise
"<package-name>" typosquatting
"<package-name>" backdoor
```

### Assessment

- For relevant results, determine whether the version being introduced is affected
- If a search returns no results, that is a clean signal, not an error
- Focus on direct dependencies explicitly changed in the diff, not transitive dependencies

## Typosquatting Detection

Check if any newly added package names are suspiciously similar to well-known packages:

| Indicator | Example | Action |
|-----------|---------|--------|
| Character substitution | `requets` vs `requests` | Flag as HIGH |
| Hyphen/underscore swap | `python-dateutil` vs `python_dateutil` | Verify correct package |
| Scope confusion (npm) | `@evil/lodash` vs `lodash` | Flag as HIGH |
| Extra/missing characters | `colorsss` vs `colors` | Flag as HIGH |

Report as **HIGH** under `Supply Chain - Suspected Typosquatting`.
