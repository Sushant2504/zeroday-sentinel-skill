# Codebase Analysis Checklist Reference

Systematic checklists for the four groundwork analysis dimensions. Each section defines what to look for, how to report it, and how findings feed into security analysis.

## Agent A: Architecture Analysis

Map the system's component boundaries, layers, execution flows, and structural properties.

### Checklist

| # | Item | What to Identify | Evidence Sources |
|---|------|-----------------|-----------------|
| A1 | Component boundaries | Top-level modules, their responsibilities, public APIs | Directory structure, package/module declarations, export statements |
| A2 | Layer identification | Presentation, business logic, data access, infrastructure layers | Import direction patterns, naming conventions |
| A3 | Entry points | All ways external input enters the system | `main.*`, route definitions, CLI parsers, message consumers, cron jobs |
| A4 | Execution flows | Request lifecycle from entry to response | Route → middleware → handler → service → repository → response |
| A5 | Trust boundaries | Where data crosses privilege levels | Public → authenticated, user input → database, external API → internal, CI → deploy |
| A6 | Shared state | Global variables, singletons, caches, session stores | Module-level variables, `@singleton`, cache initialization, Redis/session usage |
| A7 | Error propagation | How errors flow across component boundaries | Try/catch patterns, error wrapping, panic recovery, error middleware |
| A8 | Dependency graph | Inter-module dependencies and their direction | Import statements, dependency injection, service registrations |
| A9 | External boundaries | Connections to external services, APIs, databases | HTTP clients, SDK initializations, connection pools, queue connections |
| A10 | Configuration flow | How config enters the system and propagates | Env var loading, config files, CLI flags, feature flags |

### Output Format

```markdown
### Architecture Overview

**Components:** {N} identified
**Layers:** {list with descriptions}
**Entry Points:** {N} ({breakdown by type: HTTP, CLI, cron, message queue})
**Trust Boundaries:** {N} identified

#### Component Map
| Component | Responsibility | Dependencies | Entry Points |
|-----------|---------------|-------------|-------------|
| {name} | {description} | {list} | {list} |

#### Trust Boundaries
| Boundary | From (trust level) | To (trust level) | Data Crossing |
|----------|-------------------|-------------------|--------------|
| {name} | {public/internal/privileged} | {level} | {data types} |
```

### Security Feed

| Architecture Item | Security Domain | Enhancement |
|------------------|----------------|-------------|
| Trust boundaries (A5) | Phase 4: Adversarial Testing | Automatic enumeration of all boundary crossings — no manual discovery needed |
| Entry points (A3) | Phase 1: Scope & Triage | Every entry point guaranteed in scan scope; boundary-crossing entries elevated to Critical |
| Shared state (A6) | Phase 2: Security Scan | Race conditions, session fixation, cache poisoning vectors |
| External boundaries (A9) | Phase 4: Adversarial Testing | Data exfiltration paths, SSRF vectors, supply chain entry points |
| Dependency graph (A8) | Phase 2: Application Security | Circular dependencies may mask security check bypasses |
| Configuration flow (A10) | Phase 2: Secret Detection | Trace where secrets enter and propagate through the system |

## Agent B: Code Patterns

Catalog coding conventions and detect deviations that may indicate security weaknesses.

### Checklist

| # | Item | What to Identify | Evidence Sources |
|---|------|-----------------|-----------------|
| B1 | Naming conventions | Variable, function, class, file naming patterns | Statistical sampling across source files |
| B2 | Error handling | Try/catch patterns, error types, recovery strategies, error wrapping | Error-related code blocks, custom error types |
| B3 | Logging practices | Log levels used, structured vs unstructured, what gets logged | Logger initialization, log statements, log config |
| B4 | Input validation | Validation approach (schema, manual, framework), where validation occurs | Request handlers, form processing, API input handling |
| B5 | Testing patterns | Test framework, naming conventions, fixture patterns, mock approach | Test files, conftest/setup files, test utilities |
| B6 | Configuration management | How config is loaded, validated, and accessed | Config modules, env var usage, config validation |
| B7 | Dependency injection | DI framework or manual, constructor vs property, scope management | Service registrations, constructor signatures, provider configs |
| B8 | Code comments | Comment frequency, style, quality — what is and isn't documented | Statistical sampling of comments vs code ratio |
| B9 | Concurrency patterns | Threading, async/await, goroutines, locks, channels | Concurrent code blocks, synchronization primitives |
| B10 | Resource management | Connection handling, file handles, cleanup patterns | Open/close pairs, context managers, defer/finally |

### Output Format

```markdown
### Code Patterns

**Conventions Detected:**
- **Naming:** {pattern description with examples}
- **Error Handling:** {pattern description}
- **Logging:** {structured/unstructured, levels used, framework}
- **Input Validation:** {approach — schema-first, manual, framework-provided}
- **Testing:** {framework, coverage approach, mock strategy}

**Deviations Found:** {N} total ({N} with security implications)

| File:Line | Convention | Deviation | Security Implication |
|-----------|-----------|-----------|---------------------|
| {path:line} | {expected pattern} | {what differs} | {risk or "none"} |
```

### Security Feed

| Pattern Item | Security Domain | Enhancement |
|-------------|----------------|-------------|
| Error handling (B2) | Application Security | Deviations (swallowed errors, exposed stack traces) flagged as potential info disclosure |
| Logging (B3) | Secret Detection | Logging patterns that include request bodies, headers, or tokens = credential exposure risk |
| Input validation (B4) | API Security, Web Security | Missing validation where convention requires it = input validation gap |
| Concurrency (B9) | Application Security | Race conditions in auth checks, TOCTOU vulnerabilities |
| Resource management (B10) | Performance Security | Leaked connections, file handle exhaustion = DoS vector |

## Agent C: API + Data Analysis

Enumerate the complete API surface, data models, and external integrations.

### Checklist

| # | Item | What to Identify | Evidence Sources |
|---|------|-----------------|-----------------|
| C1 | API endpoints | Method, path, handler, auth requirement, rate limiting | Route definitions, OpenAPI specs, controller decorators |
| C2 | Request/response schemas | Input validation rules, response shapes, error formats | Schema definitions, serializers, DTOs, type definitions |
| C3 | Data models | Entities, fields, types, relationships, constraints, indexes | ORM models, SQL schemas, migration files |
| C4 | Sensitive data fields | PII, credentials, financial data, health data | Field names, type annotations, data classification markers |
| C5 | External integrations | Third-party APIs, webhooks sent, message queue interactions | HTTP client calls, SDK usage, webhook handlers |
| C6 | Data flow mapping | Where sensitive data enters, moves through, and is stored | Input handlers → service → repository → database path |
| C7 | Pagination & limits | How large result sets are handled | Query builders, response pagination, cursor implementation |
| C8 | File handling | Upload/download endpoints, storage backends, size limits | Multipart handlers, storage configuration, file validation |
| C9 | Caching strategy | What is cached, TTL, invalidation, cache keys | Cache middleware, cache decorators, Redis/Memcached usage |
| C10 | Database queries | Raw vs parameterized, ORM usage, query patterns | Query construction, ORM calls, raw SQL strings |

### Output Format

```markdown
### API Surface

| # | Method | Path | Auth | Rate Limited | Input Validated | Handler |
|---|--------|------|------|-------------|----------------|---------|
| {n} | {GET/POST/...} | {path} | {yes/no/partial} | {yes/no} | {yes/no/partial} | {file:line} |

**Total Endpoints:** {N}
**Auth Coverage:** {N}/{total} ({percent}%)
**Rate Limited:** {N}/{total}
**Input Validated:** {N}/{total}

### Data Models

| Model | Fields | Sensitive Fields | Relationships | Source |
|-------|--------|-----------------|--------------|--------|
| {name} | {count} | {list} | {list} | {file:line} |

### External Integrations

| Service | Type | Auth Method | Data Sent | Source |
|---------|------|------------|-----------|--------|
| {name} | {REST/gRPC/webhook/queue} | {API key/OAuth/none} | {data types} | {file:line} |
```

### Security Feed

| API/Data Item | Security Domain | Enhancement |
|--------------|----------------|-------------|
| Endpoints without auth (C1) | API Security | Direct finding: missing authentication on accessible endpoint |
| Sensitive data fields (C4) | Database Security, Secret Detection | Ensure encryption at rest, mask in logs, restrict in API responses |
| Data flow (C6) | Phase 4: Adversarial Testing | Complete exfiltration path mapping — where does PII go? |
| Raw queries (C10) | Database Security | Direct finding: SQL/NoSQL injection vectors |
| File handling (C8) | API Security | Upload validation gaps, path traversal, unrestricted file types |
| Missing pagination (C7) | Performance Security | Unbounded queries = DoS vector |
| Caching (C9) | Performance Security | Cache poisoning, sensitive data in cache keys |

## Agent D: DevOps + Git Analysis

Analyze the CI/CD pipeline, containerization, infrastructure-as-code, and git workflow.

### Checklist

| # | Item | What to Identify | Evidence Sources |
|---|------|-----------------|-----------------|
| D1 | CI/CD pipeline stages | Build, test, lint, security scan, deploy stages | Workflow files, Jenkinsfile, pipeline configs |
| D2 | Security gates | SAST, DAST, dependency scan, secret scan in pipeline | CI config job definitions, tool integrations |
| D3 | Container configuration | Base images, build stages, runtime user, exposed ports | Dockerfiles, docker-compose, container configs |
| D4 | Infrastructure as code | What infra is managed by code vs manual | Terraform files, Helm charts, K8s manifests |
| D5 | Environment management | How dev/staging/prod differences are handled | Environment-specific configs, feature flags, deploy configs |
| D6 | Secret management | Where secrets are stored and how they're injected | CI secret variables, vault configs, sealed secrets, env injection |
| D7 | Deployment strategy | Blue/green, canary, rolling, recreate, feature flags | Deploy configs, rollout strategies, load balancer configs |
| D8 | Git workflow | Branch strategy, merge patterns, review requirements | Branch naming, protection rules, CODEOWNERS, PR templates |
| D9 | Monitoring & observability | Logging, metrics, tracing, alerting setup | APM configs, logging setup, dashboard definitions |
| D10 | Rollback capability | How rollbacks are performed, state compatibility | Migration reversibility, deploy scripts, rollback procedures |

### Output Format

```markdown
### DevOps & Infrastructure

**CI/CD Pipeline:** {system} with {N} stages
**Security Gates:** {list or "none detected"}
**Container Strategy:** {description}
**IaC Coverage:** {what is managed}
**Deployment:** {strategy}
**Git Workflow:** {strategy description}

#### Pipeline Stages
| Stage | Purpose | Security Relevant | Source |
|-------|---------|-------------------|--------|
| {name} | {description} | {yes/no} | {file:line} |

#### Container Analysis
| Image | Base | Pinned | Runs as Root | Multi-Stage | Source |
|-------|------|--------|-------------|------------|--------|
| {name} | {base:tag} | {yes/no} | {yes/no} | {yes/no} | {file:line} |
```

### Security Feed

| DevOps Item | Security Domain | Enhancement |
|------------|----------------|-------------|
| Missing security gates (D2) | CI/CD Security | Direct finding: no SAST/DAST/secret scan in pipeline |
| Container as root (D3) | Container Security | Direct finding: container running as root |
| Secret management (D6) | Secret Detection | Evaluate secret injection approach for exposure risk |
| No rollback (D10) | Critical Workflows | Risk assessment: security patch deployment can't be reversed |
| Missing branch protection (D8) | Git & GitHub Security | Direct finding: unprotected main branch |

## Cross-Dimension Security Crosswalk

Maps analysis items across all four agents to the specific security enhancement they provide.

| Analysis Dimension | Item | Feeds Security Phase | How It Enhances Security |
|-------------------|------|---------------------|------------------------|
| Architecture | Trust boundaries | Phase 4 (Adversarial) | Automatic attack surface enumeration |
| Architecture | Entry points | Phase 1 (Triage) | Complete scan scope, risk elevation |
| Architecture | External boundaries | Phase 4 (Adversarial) | SSRF, data exfiltration path mapping |
| Code Patterns | Error handling deviations | Phase 2 (Scan) | Information disclosure detection |
| Code Patterns | Logging with sensitive data | Phase 2 (Secrets) | Credential exposure via logs |
| Code Patterns | Missing input validation | Phase 2 (API/Web) | Injection vector identification |
| API + Data | Unauthed endpoints | Phase 2 (API) | Missing auth finding |
| API + Data | Sensitive data paths | Phase 4 (Adversarial) | PII exfiltration mapping |
| API + Data | Raw SQL queries | Phase 2 (Database) | SQL injection finding |
| DevOps | Missing pipeline gates | Phase 2 (CI/CD) | Pipeline integrity finding |
| DevOps | Root containers | Phase 2 (Container) | Privileged container finding |
| DevOps | No branch protection | Phase 2 (Git) | Branch protection gap finding |
