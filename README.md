# Zero-Day Sentinel

A full-spectrum security engineering skill for [Claude Code](https://claude.ai/claude-code) (and [Cursor](#cursor-integration)) that performs adversarial vulnerability scanning, security architecture review, and guided remediation across all developer workflows.

## What It Does

When invoked (or auto-triggered), Zero-Day Sentinel:

1. **Detects scope** — reviews pending changes if any exist, otherwise audits the full project
2. **Identifies tech stack** — determines which security domains apply (web, API, mobile, IaC, etc.)
3. **Scans for vulnerabilities** — applies domain-specific checks from 17 security domains
4. **Analyzes supply chain** — queries OpenSSF Scorecard, checks for typosquatting, flags new packages
5. **Thinks adversarially** — models abuse scenarios, trust boundary crossings, privilege escalation
6. **Provides remediation** — every finding includes a 4-step fix: Immediate Fix, Verify, Prevent, Harden

## Supported Developer Roles

| Role | Domains Covered |
|------|----------------|
| **Web Developers** | XSS, CSRF, CSP, CORS, cookies, security headers, SRI, framework-specific (React/Vue/Angular) |
| **API Engineers** | Auth, rate limiting, input validation, BOLA/IDOR, GraphQL, WebSocket, file uploads |
| **App Developers** | SAST for Go, Python, JS/TS, Java, C#, Ruby, Rust, Shell — injection, crypto, error handling |
| **Mobile Developers** | iOS (Swift), Android (Kotlin), React Native, Flutter — storage, pinning, WebView, deep links |
| **DevOps / SRE** | Dockerfiles, K8s manifests, Helm, Terraform, ArgoCD, CI/CD pipelines, OpenShift |
| **DBAs** | SQL/NoSQL injection, access control, encryption, migrations, connection security |
| **Performance Engineers** | Rate limiting, caching security, CDN, load balancers, connection pools, CSV/Excel injection |
| **Release Engineers** | App store/Play Store deployment, release signing, staged rollouts, hotfixes, rollbacks, feature flags |
| **Cloud Engineers** | AWS, GCP, Azure — IAM, serverless, storage, networking, container registries |

## 17 Security Domains

| # | Domain | Reference |
|---|--------|-----------|
| 1 | Web Application Security | OWASP Top 10, CSP, CORS, cookies, XSS, CSRF |
| 2 | API Security | REST, GraphQL, WebSocket, rate limiting, file uploads |
| 3 | Application SAST | Language-specific static analysis patterns |
| 4 | Authentication & Authorization | Passwords, sessions, JWT, OAuth/OIDC, RBAC, MFA |
| 5 | Database Security | SQL/NoSQL injection, access control, encryption, migrations |
| 6 | Performance & Scaling | Rate limiting, caching, CDN, load balancers, DoS prevention |
| 7 | Infrastructure / IaC | Terraform, ArgoCD, Helm — IAM, network, encryption |
| 8 | Container Security | Dockerfiles, image pinning, root user, secrets in build |
| 9 | Kubernetes Security | Pod security, RBAC, network policies, service mesh |
| 10 | CI/CD Pipeline Security | GitHub Actions, Jenkins, Tekton — permissions, injection, pinning |
| 11 | Secret Detection | Cloud creds, API tokens, private keys, connection strings |
| 12 | Supply Chain Analysis | Dependency pinning, OpenSSF Scorecard, typosquatting |
| 13 | Mobile Security | iOS, Android, React Native, Flutter |
| 14 | Cloud Native Security | AWS, GCP, Azure services and configurations |
| 15 | Agent & Skill Security | Claude Code skills, MCP servers, plugin manifests |
| 16 | Critical Workflows | App store deployment, merge conflicts, hotfixes, rollbacks, feature flags |
| 17 | Git & GitHub Workflows | Branch protection, signed commits, credentials, deploy keys, webhooks, org hardening |

## Installation

### Claude Code

Copy the `.claude/skills/zeroday-sentinel/` directory into your project:

```bash
# From this repo
cp -r .claude/skills/zeroday-sentinel /path/to/your/project/.claude/skills/

# Or into your home directory for global availability
cp -r .claude/skills/zeroday-sentinel ~/.claude/skills/
```

### Cursor


Copy the `.cursor/rules/` directory into your project:

```bash
cp -r .cursor/rules /path/to/your/project/.cursor/
```

## Usage

### Claude Code

**Manual invocation:**
```
/zeroday-sentinel
```

**With arguments (target specific files or branch):**
```
/zeroday-sentinel src/auth/
/zeroday-sentinel main...HEAD
```

**Auto-triggered:** The skill auto-activates when Claude detects security-relevant work — editing auth logic, adding dependencies, modifying Dockerfiles, changing CI/CD pipelines, etc.

### Cursor

The rules auto-apply based on file globs. When you open or edit a file matching the configured patterns (e.g., `*.py`, `Dockerfile`, `*.yml`), the relevant security rules load into context automatically.

The `zeroday-sentinel.mdc` master rule is set to `alwaysApply: true` and provides the overall security scanning framework.

## Report Format

Every scan produces a structured report:

```
## Security Review

**Scan Mode:** Pending Changes Review
**Project Type:** Web App (API + Frontend)
**Tech Stack:** Python (FastAPI), TypeScript (React), PostgreSQL, Docker

### Findings

**[CRITICAL] SQL Injection via f-string**
- File: `api/routes/users.py:89`
- Category: Database - SQL Injection
- Impact: Attacker could exfiltrate all data

**Remediation:**
Step 1 — Immediate Fix: [before/after code]
Step 2 — Verify: [test command]
Step 3 — Prevent: [linting rule]
Step 4 — Harden: [defense-in-depth]

### Security Posture
**Overall Risk:** HIGH
**Top Priority:** Fix the SQL injection
**Quick Wins:** Add CSP header, pin GitHub Actions
```

See [samples/sample-report.md](.claude/skills/zeroday-sentinel/samples/sample-report.md) for a full example.

## File Structure

```
.claude/skills/zeroday-sentinel/
├── SKILL.md                              # Main skill definition (360+ lines)
├── references/
│   ├── web-security.md                   # OWASP, CSP, CORS, cookies, XSS, CSRF
│   ├── api-security.md                   # REST, GraphQL, WebSocket, rate limiting
│   ├── application-security.md           # SAST: Go, Python, JS/TS, Shell
│   ├── authentication-authorization.md   # Passwords, JWT, OAuth, RBAC, MFA
│   ├── database-security.md              # SQL/NoSQL injection, access control
│   ├── performance-security.md           # Rate limiting, caching, CDN, CSV injection
│   ├── infrastructure-security.md        # Terraform, ArgoCD, Helm
│   ├── container-kubernetes-security.md  # Dockerfiles, K8s, RBAC, OpenShift
│   ├── cicd-pipeline-security.md         # GitHub Actions, Jenkins, Tekton
│   ├── secret-detection.md              # Cloud creds, API tokens, private keys
│   ├── supply-chain-analysis.md         # OpenSSF Scorecard, typosquatting
│   ├── mobile-security.md              # iOS, Android, React Native, Flutter
│   ├── cloud-native-security.md        # AWS, GCP, Azure
│   ├── agent-skill-security.md         # Claude Code skills, MCP, plugins
│   ├── critical-workflows.md          # App store deploy, merge conflicts, hotfixes, rollbacks
│   ├── git-github-security.md         # Branch protection, signed commits, deploy keys, webhooks
│   ├── remediation-playbooks.md        # Step-by-step fix guides (1000+ lines)
│   └── report-template.md             # Output format, severity definitions
└── samples/
    └── sample-report.md                # Example output

.cursor/rules/                          # Cursor-compatible replica
├── zeroday-sentinel.mdc               # Master rule (always apply)
├── web-security.mdc                   # Web app security rules
├── api-security.mdc                   # API security rules
├── application-security.mdc          # SAST rules by language
├── auth-security.mdc                 # Authentication & authorization
├── database-security.mdc            # Database security rules
├── performance-security.mdc         # Performance & scaling security
├── infrastructure-security.mdc      # IaC security rules
├── container-kubernetes-security.mdc # Container & K8s rules
├── cicd-security.mdc                # CI/CD pipeline rules
├── secret-detection.mdc             # Secret detection rules
├── supply-chain-security.mdc        # Supply chain analysis
├── mobile-security.mdc             # Mobile app security
├── cloud-native-security.mdc       # Cloud service security
├── critical-workflows.mdc          # Release, merge conflicts, hotfixes, rollbacks
└── git-github-security.mdc         # Branch protection, credentials, signed commits
```

## Security Model

The skill itself follows security best practices:

- **Read-only tools** — `allowed-tools` restricts to `Read`, `Grep`, `Glob`, scoped `Bash` (git, curl, find), and `WebSearch`
- **No write access** — cannot modify files, push code, or execute arbitrary commands
- **Scoped Bash** — only `git diff`, `git log`, `git status`, `find`, and `curl` to the OpenSSF Scorecard API
- **Secret redaction** — truncates found secrets to 4-8 characters in reports
- **Input validation** — validates OpenSSF API URL components before constructing requests

## Cursor Integration

The `.cursor/rules/` directory contains `.mdc` files that replicate the skill's knowledge base for Cursor IDE. Key differences from the Claude Code version:

| Aspect | Claude Code | Cursor |
|--------|------------|--------|
| Activation | Auto-triggered + `/zeroday-sentinel` | Glob-based auto-attach + `alwaysApply` |
| Scanning | Active (reads files, runs git commands) | Passive (guidelines applied during chat) |
| Reference loading | On-demand per domain | All matching rules load together |
| Remediation | Dynamic code analysis + fix suggestions | Static patterns and templates |
| Supply chain | Queries OpenSSF API, searches web | Pattern-based guidance only |

Cursor rules provide the same security knowledge but as passive coding guidelines rather than active scanning.
