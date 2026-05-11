# Sample Security Report

This is an example of the output produced by the zeroday-sentinel skill.

---

## Security Review

**Scan Date:** 2026-05-11
**Scan Mode:** Pending Changes Review
**Scope:** 12 files changed in current branch vs main
**Files Reviewed:** 12 (2 critical, 4 high risk)
**Domains Analyzed:** Application, Containers, CI/CD, Secrets, Supply Chain

### Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 3 |
| MEDIUM | 4 |
| LOW | 1 |

### Findings

**[CRITICAL] Hardcoded AWS Access Key in Configuration**

- **File:** `config/settings.py:47`
- **Category:** `Secrets - Cloud Credential`
- **Issue:** AWS access key ID `AKIA3E7X...` hardcoded in source file
- **Impact:** An attacker with repository access could use these credentials to access AWS resources, potentially leading to data exfiltration or infrastructure compromise
- **Recommendation:** Remove the key immediately, rotate the credential in AWS IAM, and use environment variables or AWS Secrets Manager instead

```python
# Before (vulnerable)
AWS_ACCESS_KEY_ID = "AKIA3E7X..."

# After (fixed)
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
```

---

**[CRITICAL] SQL Injection via String Formatting**

- **File:** `api/handlers/users.go:123`
- **Category:** `Application - Injection Vulnerability`
- **Issue:** User-supplied `username` parameter is interpolated directly into SQL query via `fmt.Sprintf`
- **Impact:** An attacker could execute arbitrary SQL commands, exfiltrate data, modify records, or escalate privileges within the database
- **Recommendation:** Use parameterized queries instead of string formatting

```go
// Before (vulnerable)
query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
db.Query(query)

// After (fixed)
db.Query("SELECT * FROM users WHERE username = $1", username)
```

---

**[HIGH] Dockerfile Running as Root**

- **File:** `Dockerfile:1-34`
- **Category:** `Container - Running as Root`
- **Issue:** No `USER` instruction in Dockerfile — container runs as root by default
- **Impact:** If the container is compromised, the attacker has root access within the container, increasing the blast radius of container escape exploits
- **Recommendation:** Add a non-root user and switch to it before the ENTRYPOINT

```dockerfile
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser
```

---

**[HIGH] GitHub Actions Workflow Using pull_request_target with PR Checkout**

- **File:** `.github/workflows/ci.yml:15-28`
- **Category:** `CI/CD - Script Injection`
- **Issue:** Workflow triggers on `pull_request_target` and checks out the PR's head ref, running untrusted code with the base repo's secrets and write permissions
- **Impact:** A malicious PR author could execute arbitrary code with access to repository secrets, potentially compromising the CI/CD pipeline and downstream deployments
- **Recommendation:** Use `pull_request` trigger instead, or if `pull_request_target` is required, never check out the PR's code — only use it for labeling or commenting

---

**[HIGH] Unpinned GitHub Action Using Branch Reference**

- **File:** `.github/workflows/ci.yml:22`
- **Category:** `CI/CD - Supply Chain Integrity`
- **Issue:** Action `uses: third-party/action@main` is pinned to a branch, not a SHA hash
- **Impact:** The action author (or an attacker who compromises their repo) could push malicious code to the `main` branch, which would execute in your CI pipeline
- **Recommendation:** Pin to a specific commit SHA: `uses: third-party/action@abc123def456...`

---

**[MEDIUM] Unpinned Base Image in Dockerfile**

- **File:** `Dockerfile:1`
- **Category:** `Container - Unpinned Base Image`
- **Issue:** `FROM python:3.12` uses a tag without SHA digest pinning
- **Impact:** Future image updates could introduce breaking changes or supply chain compromises without notice
- **Recommendation:** Pin to a specific digest: `FROM python:3.12@sha256:abc123...`

---

**[MEDIUM] Missing Resource Limits in Kubernetes Deployment**

- **File:** `deploy/deployment.yaml:34`
- **Category:** `Kubernetes - Missing Security Context`
- **Issue:** Container spec has no `resources.limits` defined for CPU or memory
- **Impact:** A compromised or buggy container could consume unbounded resources, causing denial of service to other workloads on the same node
- **Recommendation:** Add resource limits appropriate for the workload

```yaml
resources:
  limits:
    memory: "512Mi"
    cpu: "500m"
  requests:
    memory: "256Mi"
    cpu: "250m"
```

---

**[MEDIUM] Debug Mode Enabled**

- **File:** `config/settings.py:12`
- **Category:** `Application - Error Handling`
- **Issue:** `DEBUG = True` is set in configuration — may leak stack traces and internal details in error responses
- **Impact:** Detailed error messages expose internal code paths, library versions, and potentially sensitive data to attackers
- **Recommendation:** Ensure `DEBUG = False` in production configuration and use environment-specific settings

---

**[MEDIUM] New Dependency with Low OpenSSF Scorecard Rating**

- **File:** `requirements.txt:15`
- **Category:** `Supply Chain - Low Scorecard Rating`
- **Issue:** Newly added dependency `fast-serializer==0.2.1` has an OpenSSF Scorecard aggregate score of 3.2/10. `Maintained` check: 2/10, `Branch-Protection`: 0/10
- **Impact:** The upstream project has weak security controls, increasing the risk of supply chain compromise
- **Recommendation:** Evaluate alternative packages with higher security scores, or accept with explicit risk justification and pin to a verified commit hash

---

**[LOW] Missing HEALTHCHECK in Dockerfile**

- **File:** `Dockerfile:34`
- **Category:** `Container - Unpinned Base Image`
- **Issue:** No `HEALTHCHECK` instruction defined
- **Impact:** Container orchestrators cannot detect unhealthy containers for automatic restart, potentially leaving degraded instances running
- **Recommendation:** Add a HEALTHCHECK instruction:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1
```

---

### Domains Not Analyzed

- **Infrastructure/IaC**: No Terraform or ArgoCD files detected
- **Agent/Skill**: No SKILL.md or agent definition files detected

### Notes

- The `fast-serializer` package was published 3 days ago. While not flagged as a separate finding, this proximity to the 7-day threshold warrants extra scrutiny.
- Supply chain threat intelligence search returned no known compromises for any of the changed dependencies.
