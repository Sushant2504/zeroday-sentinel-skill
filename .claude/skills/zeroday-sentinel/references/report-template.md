# Security Report Template

Use this template to structure the final output of a zeroday-sentinel scan.

## Full Report Template

```markdown
## Security Review

**Scan Date:** {TIMESTAMP}
**Scan Mode:** {Pending Changes Review | Full Project Audit | Targeted Scan}
**Project Type:** {Web App | API Service | Mobile App | Microservice | CLI Tool | Library | IaC | Mixed}
**Tech Stack:** {detected languages, frameworks, and tools}
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
- **Affected Roles:** {Web Dev | App Dev | API Dev | DevOps | DBA | Mobile Dev | All}

**Remediation:**

**Step 1 — Immediate Fix:**
\`\`\`{language}
// Before (vulnerable)
{VULNERABLE_CODE}

// After (fixed)
{FIXED_CODE}
\`\`\`

**Step 2 — Verify:**
\`\`\`bash
{VERIFICATION_COMMAND}
\`\`\`
Expected: {EXPECTED_RESULT}

**Step 3 — Prevent Recurrence:**
- {LINTING_RULE_OR_CI_CHECK}
- {PRE_COMMIT_HOOK}
- {ARCHITECTURAL_PATTERN}

**Step 4 — Harden Further:**
- {ADDITIONAL_DEFENSE_IN_DEPTH}
- {MONITORING_ALERTING}
- {RELATED_HARDENING}

---

### Domains Not Analyzed

{List any domains that were skipped and why:}
- {DOMAIN}: {REASON} (e.g., "No Terraform files detected", "WebSearch unavailable for threat intelligence")

### Security Posture

**Overall Risk:** {CRITICAL | HIGH | MEDIUM | LOW | CLEAN}
**Top Priority:** {the single most important thing to fix}
**Quick Wins:** {1-3 low-effort fixes with high impact}
**Architecture Notes:** {any systemic patterns that need addressing}

### Notes

{Any additional context, caveats, or observations that don't fit into findings.}
```

## Severity Level Definitions

| Severity | Definition | Examples | Action | SLA |
|----------|-----------|----------|--------|-----|
| **CRITICAL** | Exploitable vulnerability with immediate risk. Active credential exposure or direct path to unauthorized access. | Hardcoded AWS keys, open admin endpoints, SQL injection with user input, privileged container with host mount, auth bypass | Block merge. Fix immediately. Rotate exposed credentials. | Fix within 24 hours |
| **HIGH** | Security weakness likely to be exploitable. Missing security controls that attackers commonly target. | Missing authentication checks, command injection vectors, overly permissive IAM, `pull_request_target` with PR checkout, missing rate limiting on auth | Block merge. Fix before deploy. | Fix within 7 days |
| **MEDIUM** | Defense-in-depth gap or best practice violation. Not directly exploitable but weakens security posture. | Unpinned image tags, missing encryption at rest, overly broad network rules, missing resource limits, missing security headers | Fix in this PR or create follow-up issue with timeline. | Fix within 30 days |
| **LOW** | Minor hardening opportunity. Minimal risk but improves overall security hygiene. | Missing security headers, verbose error messages, missing HEALTHCHECK, non-optimal file permissions, missing SRI | Address when convenient. Do not block merge. | Fix within 90 days |

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

### Web Application Categories
- `Web - Cross-Site Scripting (XSS)`
- `Web - Cross-Site Request Forgery (CSRF)`
- `Web - Missing Security Headers`
- `Web - Insecure Cookie Configuration`
- `Web - CORS Misconfiguration`
- `Web - Client-Side Storage Exposure`
- `Web - Missing Subresource Integrity`
- `Web - Broken Access Control`

### API Categories
- `API - Missing Authentication`
- `API - Broken Object-Level Authorization (BOLA)`
- `API - Missing Rate Limiting`
- `API - Input Validation Gap`
- `API - Excessive Data Exposure`
- `API - Missing Pagination`
- `API - File Upload Vulnerability`
- `API - GraphQL Security`
- `API - WebSocket Security`

### Authentication & Authorization Categories
- `Auth - Weak Password Hashing`
- `Auth - Session Management Flaw`
- `Auth - JWT Vulnerability`
- `Auth - OAuth/OIDC Misconfiguration`
- `Auth - Missing MFA`
- `Auth - RBAC Violation`
- `Auth - Account Enumeration`
- `Auth - API Key Exposure`

### Database Categories
- `Database - SQL Injection`
- `Database - NoSQL Injection`
- `Database - Excessive Privileges`
- `Database - Missing Encryption`
- `Database - Unsafe Migration`
- `Database - Connection Security`
- `Database - Missing Row-Level Security`

### Performance & Scaling Categories
- `Performance - Missing Rate Limiting`
- `Performance - Unbounded Query Results`
- `Performance - Resource Exhaustion Risk`
- `Performance - Missing Timeouts`
- `Performance - Cache Security`
- `Performance - CDN Misconfiguration`
- `Performance - Load Balancer Security`
- `Performance - Connection Pool Risk`
- `Performance - CSV/Excel Injection`

### CI/CD Categories
- `CI/CD - Pipeline Integrity`
- `CI/CD - Credential Leakage`
- `CI/CD - Supply Chain Integrity`
- `CI/CD - Workflow Permissions`
- `CI/CD - Script Injection`
- `CI/CD - Action Pinning`
- `CI/CD - Self-Hosted Runner Risk`

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

### Mobile Categories
- `Mobile - Insecure Data Storage`
- `Mobile - Missing Certificate Pinning`
- `Mobile - WebView Vulnerability`
- `Mobile - Deep Link Hijacking`
- `Mobile - Binary Security`
- `Mobile - Cleartext Traffic`

### Cloud Native Categories
- `Cloud - IAM Misconfiguration`
- `Cloud - Public Storage`
- `Cloud - Serverless Security`
- `Cloud - Missing Encryption`
- `Cloud - Network Exposure`
- `Cloud - Service Account Key Exposure`

### Agent & Skill Categories
- `Agent - Overly Broad Tool Access`
- `Agent - Missing Safety Guardrails`
- `Agent - Data Exfiltration Risk`
- `Skill - Unrestricted Bash`
- `Skill - Instruction Injection`
- `Skill - Privilege Boundary Violation`
- `MCP - Untrusted Endpoint`
- `MCP - Credential Exposure`

### Critical Workflow Categories
- `Release - Debug Build in Production`
- `Release - Test Credentials Shipped`
- `Release - Missing Signing`
- `Release - Staged Rollout Gap`
- `Release - Staging Endpoint in Production`
- `Merge - Security Check Dropped`
- `Merge - Lock File Integrity`
- `Merge - Permissive Config Merged`
- `Hotfix - CI Bypass`
- `Hotfix - Missing Review`
- `Hotfix - Temporary Credentials`
- `Rollback - No Down Migration`
- `Rollback - State Incompatibility`
- `Rollback - Session/Token Break`
- `Feature Flag - Security Gate`
- `Feature Flag - Client-Side Evaluation`
- `Feature Flag - Stale Security Flag`

### Git & GitHub Categories
- `Git - Force Push to Protected Branch`
- `Git - Unsigned Commits`
- `Git - Credential Storage`
- `Git - Rebase of Shared History`
- `Git - Submodule Risk`
- `Git - Config Security`
- `GitHub - Branch Protection Gap`
- `GitHub - Overly Permissive Access`
- `GitHub - Deploy Key Exposure`
- `GitHub - Webhook Secret Missing`
- `GitHub - Missing 2FA`
- `GitHub - PAT Scope/Expiration`
- `GitHub - Organization Hardening`

### Secret Detection Categories
- `Secrets - Cloud Credential`
- `Secrets - API Token`
- `Secrets - Private Key`
- `Secrets - Connection String`
- `Secrets - Generic Secret`

---

## Groundwork-Enhanced Report Template

When groundwork mode is active, use this extended template. All standard sections remain, with additional sections inserted.

```markdown
## Groundwork + Security Review

**Scan Date:** {TIMESTAMP}
**Scan Mode:** Full Project Audit (Groundwork Enhanced)
**Project Type:** {Web App | API Service | Mobile App | Microservice | CLI Tool | Library | IaC | Mixed}
**Tech Stack:** {detected languages, frameworks, and tools}
**Groundwork Scope:** {files_read} files read, {functions_analyzed} functions analyzed, {endpoints_mapped} API endpoints mapped
**Files Reviewed:** {TOTAL_COUNT} ({CRITICAL_COUNT} critical, {HIGH_COUNT} high risk)
**Domains Analyzed:** {DOMAINS_LIST}

### Architecture Overview
{Component map, layer identification, trust boundaries, entry points — see code-analysis-checklist.md Agent A}

### Code Patterns
{Conventions detected, deviations found with security implications — see code-analysis-checklist.md Agent B}

### API Surface
{Complete endpoint table with auth/rate limit/validation coverage — see code-analysis-checklist.md Agent C}

### Summary
{Standard severity count table}

### Findings
{Standard findings format — each finding may include a **Groundwork Context** line explaining how codebase analysis informed the finding}

### Documentation Correlation
{Only if docs provided — correlation matrix, gap analysis, security doc gaps}

### Cross-Project Overlap
{Only if multiple projects — user story inventory, overlap matrix, shared vulnerability analysis}

### Verification Summary
{Verification report — total claims, verified count, corrections, failures}

### Domains Not Analyzed
{Standard domain skip list}

### Security Posture
{Standard posture summary — may reference architecture findings}
```

### Groundwork Finding Severity Guidance

Groundwork-specific findings (architecture gaps, documentation gaps, code pattern deviations) have default severity ranges. They can be elevated when they directly enable or mask a security vulnerability found during the standard scan phases.

| Finding Type | Default Severity | Elevation Criteria |
|-------------|-----------------|-------------------|
| Architecture trust boundary gap | MEDIUM | Elevate to HIGH if no security control exists at the boundary |
| Missing component isolation | MEDIUM | Elevate to HIGH if shared state enables privilege escalation |
| Convention deviation | LOW | Elevate to HIGH/CRITICAL if deviation is the direct cause of a vulnerability |
| Logging sensitive data | HIGH | Already high — maintain |
| Undocumented endpoint | LOW | Elevate to MEDIUM if endpoint handles sensitive data |
| Missing auth on endpoint | HIGH | Already high — maintain |
| Security documentation gap | LOW | Elevate to MEDIUM for auth model or incident response gaps |
| Stale documentation | LOW | Elevate to MEDIUM if doc references removed security controls |
| Cross-project shared vulnerability | Escalate +1 level | Systemic issue — always escalate |
| Cross-project version inconsistency | MEDIUM | Elevate to HIGH if the older version has known CVEs |

### Architecture Categories
- `Architecture - Trust Boundary Gap`
- `Architecture - Missing Component Isolation`
- `Architecture - Circular Dependency`
- `Architecture - Shared State Risk`

### Code Pattern Categories
- `Code Pattern - Convention Deviation`
- `Code Pattern - Inconsistent Error Handling`
- `Code Pattern - Missing Input Validation Pattern`
- `Code Pattern - Logging Sensitive Data`

### API Surface Categories
- `API Surface - Undocumented Endpoint`
- `API Surface - Missing Auth Requirement`
- `API Surface - Inconsistent Validation`
- `API Surface - Missing Rate Limiting`

### Documentation Categories
- `Documentation - Security Doc Gap`
- `Documentation - Stale Documentation`
- `Documentation - Missing Runbook`
- `Documentation - Broken Reference`

### Cross-Project Categories
- `Cross-Project - Shared Vulnerability`
- `Cross-Project - Version Inconsistency`
- `Cross-Project - Divergent Security Posture`
- `Cross-Project - Duplicate Implementation`
