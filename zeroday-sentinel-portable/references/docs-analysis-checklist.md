# Documentation Analysis Checklist Reference

Framework for evaluating documentation quality, coverage, and security relevance during groundwork analysis.

## Documentation Discovery

### Primary Sources (Always Check)

| Source | Path Patterns | What It Reveals |
|--------|--------------|----------------|
| Project README | `README.md`, `README.rst`, `README.txt` | Project purpose, setup, usage overview |
| Contributing guide | `CONTRIBUTING.md`, `CONTRIBUTE.md` | Development workflow, review process |
| Security policy | `SECURITY.md` | Vulnerability reporting, security contacts |
| Changelog | `CHANGELOG.md`, `HISTORY.md`, `CHANGES.md` | Release history, breaking changes |
| License | `LICENSE`, `LICENSE.md` | Legal constraints (may affect security tooling choices) |

### Extended Sources (If Present)

| Source | Path Patterns | What It Reveals |
|--------|--------------|----------------|
| Documentation directory | `docs/`, `documentation/`, `doc/` | Detailed guides, API docs, architecture |
| Architecture docs | `ARCHITECTURE.md`, `DESIGN.md`, `docs/architecture/` | System design, component relationships |
| ADRs | `adr/`, `ADR/`, `decisions/`, `docs/decisions/` | Why specific architectural choices were made |
| API specs | `openapi.yaml`, `swagger.json`, `api/` | API contracts, schemas, auth requirements |
| Runbooks | `runbooks/`, `playbooks/`, `ops/` | Operational procedures, incident response |
| Wiki | `wiki/`, `.github/wiki/` | Extended documentation (may be stale) |

### Inline Documentation (Sample During Code Analysis)

| Type | Language/Framework | What to Assess |
|------|-------------------|---------------|
| Docstrings | Python (`"""..."""`), Go (`//`), Java (`/** */`) | Function purpose, parameters, return values, security notes |
| JSDoc/TSDoc | JavaScript/TypeScript (`/** */`) | Type documentation, param descriptions |
| Code comments | All languages | Architecture decisions, security warnings, TODO items |
| Type annotations | TypeScript, Python (type hints), Go | Self-documenting type safety |

## Quality Assessment

Score each dimension 0-3 for every documentation source.

### Scoring Rubric

| Dimension | 0 (Missing) | 1 (Poor) | 2 (Adequate) | 3 (Good) |
|-----------|-------------|----------|-------------|----------|
| **Accuracy** | No docs | Docs exist but contain errors or outdated info | Mostly accurate, minor inconsistencies | Verified against code, examples work |
| **Completeness** | No docs | Major features or APIs undocumented | Core features documented, gaps in edge cases | All public APIs and features documented |
| **Currency** | No docs | Not updated in 12+ months despite code changes | Updated within 6 months, some lag | Updated alongside code changes |
| **Accessibility** | No docs | Docs exist but are disorganized or hard to find | Organized with some navigation, basic structure | Clear structure, searchable, good examples |
| **Security relevance** | No security docs | Security mentioned in passing | Basic security docs (auth, input validation) | Comprehensive security documentation |

### Assessment Template

```markdown
### Documentation Quality Assessment

| Source | Accuracy | Completeness | Currency | Accessibility | Security | Overall |
|--------|----------|-------------|---------|-------------|----------|---------|
| README.md | 3 | 2 | 3 | 3 | 1 | 2.4/3 |
| docs/api.md | 2 | 1 | 1 | 2 | 0 | 1.2/3 |
| ARCHITECTURE.md | — | — | — | — | — | Missing |

**Overall Documentation Score:** {average}/3
**Security Documentation Score:** {security average}/3
```

## Security Documentation Audit

Specific checks for security-relevant documentation. Missing items generate findings in the security report.

### Authentication & Authorization

| Check | What to Look For | Finding if Missing |
|-------|-----------------|-------------------|
| Auth flow documented | Step-by-step authentication process: login, token refresh, logout | `Documentation - Security Doc Gap` (MEDIUM) |
| Token lifecycle | Token type, expiration, refresh mechanism, revocation | `Documentation - Security Doc Gap` (MEDIUM) |
| Authorization model | Roles, permissions, which roles can access which resources | `Documentation - Security Doc Gap` (MEDIUM) |
| MFA documentation | Whether MFA is supported, how it works, recovery process | `Documentation - Security Doc Gap` (LOW) |
| Session management | Session storage, timeout, concurrent session handling | `Documentation - Security Doc Gap` (LOW) |

### API Security

| Check | What to Look For | Finding if Missing |
|-------|-----------------|-------------------|
| Endpoint auth requirements | Which endpoints require auth, which are public | `Documentation - Security Doc Gap` (MEDIUM) |
| Rate limiting documentation | Rate limits per endpoint or tier, what happens on limit | `Documentation - Security Doc Gap` (LOW) |
| Input validation rules | What input is validated, expected formats, size limits | `Documentation - Security Doc Gap` (LOW) |
| Error response format | How errors are returned, what info is exposed | `Documentation - Security Doc Gap` (LOW) |

### Operational Security

| Check | What to Look For | Finding if Missing |
|-------|-----------------|-------------------|
| Incident response plan | Who to contact, steps to take, escalation path | `Documentation - Security Doc Gap` (LOW) |
| Secrets management | Where secrets are stored, how to rotate them | `Documentation - Security Doc Gap` (LOW) |
| Deployment security checklist | Pre-deploy verification steps | `Documentation - Security Doc Gap` (LOW) |
| Backup & recovery | How data is backed up, restoration procedure | `Documentation - Security Doc Gap` (LOW) |

### Data Handling

| Check | What to Look For | Finding if Missing |
|-------|-----------------|-------------------|
| Data classification | What data is collected, sensitivity levels | `Documentation - Security Doc Gap` (LOW) |
| Data flow documentation | Where data enters, how it moves, where it's stored | `Documentation - Security Doc Gap` (LOW) |
| Retention policy | How long data is kept, deletion procedures | `Documentation - Security Doc Gap` (LOW) |
| Privacy compliance | GDPR, CCPA, HIPAA requirements and how they're met | `Documentation - Security Doc Gap` (LOW) |

## Staleness Detection

### Automated Checks

Compare documentation timestamps against code timestamps for related modules:

```bash
# Get last modification date for a doc file
git log -1 --format="%ai %H" -- docs/authentication.md

# Get last modification date for related code
git log -1 --format="%ai %H" -- src/auth/

# Calculate staleness gap
```

### Staleness Classification

| Gap | Classification | Action |
|-----|---------------|--------|
| Doc updated after code | Current | No action |
| Code changed 0-3 months after doc | Watch | Note in correlation matrix |
| Code changed 3-6 months after doc | Warning | Flag as `Documentation - Stale Documentation` (LOW) |
| Code changed 6+ months after doc | Stale | Flag as `Documentation - Stale Documentation` (MEDIUM) |
| Doc references removed code | Broken | Flag as `Documentation - Stale Documentation` (MEDIUM) |

### Broken Reference Detection

Scan documentation for references that no longer resolve:

| Reference Type | Detection | Example |
|---------------|-----------|---------|
| File path references | Check if referenced files exist | `` `src/auth/jwt.py` `` → file deleted |
| Function/class references | Grep for referenced symbols | "Call `validate_token()`" → function renamed |
| API endpoint references | Check route definitions | "`POST /api/v1/users`" → route removed |
| Configuration references | Check config files | "`Set REDIS_URL=...`" → env var renamed |
| Link references | Check internal links resolve | `[Auth docs](docs/auth.md)` → file moved |

## Report Output

### Documentation Assessment Section

```markdown
### Documentation Assessment

**Overall Score:** {N}/3
**Security Score:** {N}/3
**Total Pages:** {N}
**Stale Pages:** {N}
**Security Gaps:** {N}

#### Page Inventory

| Page | Topic | Quality Score | Staleness | Security Relevant |
|------|-------|--------------|-----------|-------------------|
| README.md | Overview | 2.4/3 | Current | No |
| docs/auth.md | Authentication | 2.0/3 | Warning (4 months) | Yes |
| ARCHITECTURE.md | — | Missing | — | Yes |

#### Security Documentation Gaps

| Missing Document | Category | Severity |
|-----------------|----------|----------|
| Authorization model | Auth & Authz | MEDIUM |
| Incident response plan | Operations | LOW |
| Data classification | Data Handling | LOW |
```
