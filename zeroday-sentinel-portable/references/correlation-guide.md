# Documentation-Code Correlation Guide

Procedures for building bidirectional correlations between documentation and code, identifying gaps, and analyzing cross-project overlaps.

## Documentation Discovery

### Where to Find Documentation

| Location | Type | Priority |
|----------|------|----------|
| `README.md`, `README.rst` | Project overview | Read first |
| `docs/`, `documentation/`, `wiki/` | Extended documentation | Read all |
| `ARCHITECTURE.md`, `DESIGN.md` | Design documentation | High priority |
| `adr/`, `ADR/`, `decisions/` | Architecture Decision Records | High priority |
| `CONTRIBUTING.md` | Contribution guidelines | Read for workflow context |
| `CHANGELOG.md`, `HISTORY.md` | Change history | Skim for recent changes |
| `SECURITY.md` | Security policies | Critical for security correlation |
| `api/`, `openapi.*`, `swagger.*` | API documentation | Cross-reference with endpoints |
| `runbooks/`, `playbooks/`, `ops/` | Operational documentation | Cross-reference with infrastructure |
| Inline: docstrings, JSDoc, GoDoc | Code-level documentation | Sample during code analysis |

### Documentation Not Accessible

Flag but do not attempt to access:
- Confluence, Notion, Google Docs (require authentication)
- Internal wikis behind VPN
- Ticket systems (Jira, Linear) — reference as external pointers

## Correlation Matrix

### Building the Matrix

For each documentation page and each code module, assess their relationship:

| Score | Meaning | Criteria |
|-------|---------|----------|
| 3 | Full coverage | Doc accurately describes the code module's purpose, API, and behavior |
| 2 | Partial coverage | Doc mentions the module but is incomplete or missing key details |
| 1 | Tangential | Doc references the module in passing or as context |
| 0 | No coverage | No documentation exists for this code module |
| -1 | Stale | Documentation exists but describes code that has since changed |
| -2 | Contradictory | Documentation states something that conflicts with actual code behavior |

### Matrix Format

```markdown
### Documentation-Code Correlation Matrix

| Code Module | Doc Page | Coverage | Last Code Change | Last Doc Update | Status |
|------------|----------|----------|-----------------|----------------|--------|
| `src/auth/` | `docs/authentication.md` | 3 (Full) | 2026-04-15 | 2026-04-10 | Current |
| `src/api/payments/` | (none) | 0 (Missing) | 2026-05-01 | — | Gap |
| `src/cache/` | `docs/architecture.md#caching` | 2 (Partial) | 2026-05-10 | 2026-01-15 | Stale |
```

### Correlation Methods

1. **Keyword matching**: Search doc content for module names, function names, and class names
2. **Path references**: Find explicit file path references in docs (`src/auth/middleware.py`)
3. **Concept mapping**: Match doc topics (e.g., "authentication flow") to code modules that implement them
4. **Import tracing**: For docs describing a feature, trace which modules participate via import chains
5. **Diagram cross-reference**: Compare architecture diagrams against actual dependency graphs

## Gap Analysis

### Documentation Gap Categories

| Category | Priority | Description |
|----------|----------|-------------|
| **Security documentation** | Critical | Missing auth flows, access control, incident response, data handling |
| **API documentation** | High | Undocumented endpoints, missing request/response schemas |
| **Architecture documentation** | High | No component diagram, missing data flow description |
| **Onboarding documentation** | Medium | Cannot set up project from docs alone |
| **Operational documentation** | Medium | Missing runbooks, deployment procedures, monitoring setup |
| **Configuration documentation** | Medium | Undocumented env vars, config options |
| **Testing documentation** | Low | Missing test strategy, how to run tests |
| **Changelog/history** | Low | No record of changes over time |

### Security Documentation Checklist

These documentation items are required for a complete security posture. Missing items should be reported as findings.

| # | Document | Purpose | Finding Severity if Missing |
|---|----------|---------|---------------------------|
| 1 | Authentication flow documentation | Describes how users authenticate, token lifecycle, session management | MEDIUM |
| 2 | Authorization model (RBAC/ABAC matrix) | Defines roles, permissions, and access control rules | MEDIUM |
| 3 | API security per-endpoint | Auth requirements, rate limits, input validation per endpoint | MEDIUM |
| 4 | Incident response procedures | Steps to take during a security incident | LOW |
| 5 | Secrets management documentation | How secrets are stored, rotated, and injected | LOW |
| 6 | Data classification policy | What data is sensitive, how it must be handled | LOW |
| 7 | Deployment security checklist | Pre-deploy security verification steps | LOW |
| 8 | Third-party integration security | Security review of external service connections | LOW |
| 9 | Vulnerability disclosure policy | How to report security issues (`SECURITY.md`) | LOW |

### Staleness Detection

Compare modification timestamps:

```bash
# Last code change in module
git log -1 --format="%ai" -- src/auth/

# Last doc change for related page
git log -1 --format="%ai" -- docs/authentication.md
```

Flag documentation as stale when:
- Code was modified more recently than its documentation AND
- The code change was substantive (not just formatting/comments)

Staleness thresholds:
- **Warning**: Doc is 3+ months older than last code change
- **Stale**: Doc is 6+ months older than last code change
- **Critical stale**: Doc references functions/classes that no longer exist

## Cross-Project Analysis

Only applicable when multiple project paths are provided.

### User Story Overlap Detection

For each project, infer user stories from:

1. **API endpoints**: Similar endpoints suggest overlapping functionality
2. **Module names**: Shared naming (e.g., both have `auth/`, `payments/`, `notifications/`) suggests feature overlap
3. **Data models**: Same or similar entity names suggest shared domain concepts
4. **README descriptions**: Feature lists and project descriptions
5. **Documentation topics**: Shared doc topics indicate overlapping concerns

### Overlap Classification

| Type | Description | Action |
|------|-------------|--------|
| **Shared dependency** | Same library used in multiple projects | Check version consistency |
| **Duplicate implementation** | Same functionality implemented independently | Evaluate consolidation or shared library extraction |
| **Complementary** | Projects serve different parts of the same workflow | Document integration points and trust boundaries |
| **Potential conflict** | Overlapping functionality with different behavior | Investigate which is authoritative, flag inconsistencies |

### Cross-Project Overlap Matrix

```markdown
### Cross-Project Overlap

| User Story | Project A | Project B | Overlap Type | Evidence |
|-----------|-----------|-----------|-------------|----------|
| User authentication | `src/auth/` (JWT) | `lib/auth/` (JWT) | Duplicate | Both implement JWT validation with different libraries |
| Payment processing | `src/payments/` | — | Unique to A | — |
| Email notifications | `src/notify/` | `services/email/` | Complementary | A triggers, B sends |
```

### Cross-Project Security Implications

| Finding | Severity | Description |
|---------|----------|-------------|
| Same vulnerability pattern across projects | Escalate +1 level | Systemic issue — not a one-off but an organizational pattern |
| Same dependency at different versions | MEDIUM | Version inconsistency may mask security patches |
| Shared auth but different implementations | HIGH | Auth divergence across related projects suggests one may be weaker |
| No shared security tooling | MEDIUM | Each project reinvents security controls independently |
| Divergent security posture | HIGH | One project much weaker than its peers in the same ecosystem |

## Report Integration

### Where Correlation Appears in the Report

1. **Section: Documentation Correlation** — The full correlation matrix
2. **Section: Cross-Project Overlap** — User story inventory and overlap matrix (multi-project only)
3. **Security Findings** — Documentation gaps reported as findings with appropriate severity
4. **Security Posture** — Architecture notes reference documentation quality and coverage
