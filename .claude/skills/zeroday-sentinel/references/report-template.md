# Security Report Template

Use this template to structure the final output of a zeroday-sentinel scan.

## Full Report Template

```markdown
## Security Review

**Scan Date:** {TIMESTAMP}
**Scan Mode:** {Pending Changes Review | Full Project Audit | Targeted Scan}
**Scope:** {SCOPE_DESCRIPTION}
**Files Reviewed:** {TOTAL_COUNT} ({CRITICAL_COUNT} critical, {HIGH_COUNT} high risk)
**Domains Analyzed:** {DOMAINS_LIST}

### Summary

| Severity | Count |
|----------|-------|
| CRITICAL | {CRITICAL_FINDINGS} |
| HIGH | {HIGH_FINDINGS} |
| MEDIUM | {MEDIUM_FINDINGS} |
| LOW | {LOW_FINDINGS} |

{If no findings: **No security issues identified in the reviewed changes.**}

### Findings

{For each finding, in severity order:}

**[SEVERITY] {TITLE}**

- **File:** `{FILE_PATH}:{LINE_NUMBER}`
- **Category:** `{DOMAIN} - {SUBCATEGORY}`
- **Issue:** {CLEAR_DESCRIPTION}
- **Impact:** {WHAT_AN_ATTACKER_COULD_ACHIEVE}
- **Recommendation:** {SPECIFIC_FIX}

{Optional code example showing the fix:}
\`\`\`
{FIX_EXAMPLE}
\`\`\`

---

### Domains Not Analyzed

{List any domains that were skipped and why:}
- {DOMAIN}: {REASON} (e.g., "No Terraform files detected", "WebSearch unavailable for threat intelligence")

### Notes

{Any additional context, caveats, or observations that don't fit into findings.}
```

## Severity Level Definitions

| Severity | Definition | Examples | Action |
|----------|-----------|----------|--------|
| **CRITICAL** | Exploitable vulnerability with immediate risk. Active credential exposure or direct path to unauthorized access. | Hardcoded AWS keys, open admin endpoints, SQL injection with user input, privileged container with host mount | Block merge. Fix immediately. Rotate exposed credentials. |
| **HIGH** | Security weakness likely to be exploitable. Missing security controls that attackers commonly target. | Missing authentication checks, command injection vectors, overly permissive IAM, `pull_request_target` with PR checkout | Block merge. Fix before deploy. |
| **MEDIUM** | Defense-in-depth gap or best practice violation. Not directly exploitable but weakens security posture. | Unpinned image tags, missing encryption at rest, overly broad network rules, missing resource limits | Fix in this PR or create follow-up issue with timeline. |
| **LOW** | Minor hardening opportunity. Minimal risk but improves overall security hygiene. | Missing security headers, verbose error messages, missing HEALTHCHECK, non-optimal file permissions | Address when convenient. Do not block merge. |

## Category Taxonomy

### Infrastructure Categories
- `Infrastructure - IAM Misconfiguration`
- `Infrastructure - Network Exposure`
- `Infrastructure - Encryption Gap`
- `Infrastructure - Secrets in Plaintext`
- `Infrastructure - Unpinned Image Tag`
- `Infrastructure - Container Security`
- `Infrastructure - Storage Security`

### Application Categories
- `Application - Injection Vulnerability`
- `Application - Credential Handling`
- `Application - Input Validation`
- `Application - Unpinned Dependency Version`
- `Application - Error Handling`
- `Application - Unsafe Deserialization`
- `Application - Cryptographic Weakness`

### CI/CD Categories
- `CI/CD - Pipeline Integrity`
- `CI/CD - Credential Leakage`
- `CI/CD - Supply Chain Integrity`
- `CI/CD - Workflow Permissions`
- `CI/CD - Script Injection`

### Supply Chain Categories
- `Supply Chain - Suspiciously New Version`
- `Supply Chain - Bulk Dependency Change`
- `Supply Chain - Low Scorecard Rating`
- `Supply Chain - Unmaintained Dependency`
- `Supply Chain - Dangerous Upstream Workflow`
- `Supply Chain - Weak Upstream Controls`
- `Supply Chain - Unsigned Releases`
- `Supply Chain - Suspected Typosquatting`
- `Supply Chain - Known Compromise`

### Container & Kubernetes Categories
- `Container - Running as Root`
- `Container - Unpinned Base Image`
- `Container - Secrets in Image`
- `Kubernetes - Privileged Container`
- `Kubernetes - RBAC Misconfiguration`
- `Kubernetes - Missing Network Policy`
- `Kubernetes - Host Access`
- `Kubernetes - Missing Security Context`

### Agent & Skill Categories
- `Agent - Overly Broad Tool Access`
- `Agent - Missing Safety Guardrails`
- `Agent - Data Exfiltration Risk`
- `Skill - Unrestricted Bash`
- `Skill - Instruction Injection`
- `Skill - Privilege Boundary Violation`
- `MCP - Untrusted Endpoint`
- `MCP - Credential Exposure`

### Secret Detection Categories
- `Secrets - Cloud Credential`
- `Secrets - API Token`
- `Secrets - Private Key`
- `Secrets - Connection String`
- `Secrets - Generic Secret`
