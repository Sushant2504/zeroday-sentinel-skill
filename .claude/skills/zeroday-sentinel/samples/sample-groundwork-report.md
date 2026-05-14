# Sample Groundwork + Security Report

This is an example output of a groundwork-enhanced security scan, demonstrating the combined analysis format. The project analyzed is a fictional FastAPI + React application.

---

## Groundwork + Security Review

**Scan Date:** 2026-05-14
**Scan Mode:** Full Project Audit (Groundwork Enhanced)
**Project Type:** Web App (API + Frontend)
**Tech Stack:** Python (FastAPI), TypeScript (React), PostgreSQL, Redis, Docker, GitHub Actions
**Groundwork Scope:** 187 files read, 423 functions analyzed, 32 API endpoints mapped
**Files Reviewed:** 187 (12 critical, 45 high risk)
**Domains Analyzed:** Web Application, API Security, Application (SAST), Authentication & Authorization, Database, Performance & Scaling, Containers, CI/CD, Secrets, Supply Chain

### Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 5 |
| MEDIUM | 8 |
| LOW | 4 |

---

### Architecture Overview

**Components:** 6 identified
**Layers:** Presentation (React SPA), API Gateway (FastAPI), Service Layer, Data Access (SQLAlchemy), Cache (Redis), Background Tasks (Celery)
**Entry Points:** 4 (HTTP API, WebSocket, Celery worker, CLI management commands)
**Trust Boundaries:** 5 identified

#### Component Map

| Component | Responsibility | Dependencies | Entry Points |
|-----------|---------------|-------------|-------------|
| `frontend/` | React SPA, user interface | API endpoints via fetch | Browser (HTTP) |
| `api/` | FastAPI routes, request validation | services, auth, models | HTTP (uvicorn) |
| `services/` | Business logic, orchestration | models, cache, external APIs | None (internal) |
| `models/` | SQLAlchemy ORM, data access | PostgreSQL | None (internal) |
| `workers/` | Celery background tasks | services, models, external APIs | Celery broker (Redis) |
| `auth/` | JWT authentication, RBAC | models, cache | None (internal) |

#### Trust Boundaries

| Boundary | From | To | Data Crossing |
|----------|------|-----|--------------|
| Public Internet → API | Untrusted | Authenticated | User input, JWT tokens |
| API → Database | Authenticated | Privileged | SQL queries, user data |
| API → Redis Cache | Authenticated | Internal | Session data, cached responses |
| Celery Worker → External API | Internal | External (3rd party) | Payment data, webhook payloads |
| Frontend → API | Untrusted (browser) | Authenticated | Form data, file uploads |

---

### Code Patterns

**Conventions Detected:**
- **Naming:** snake_case for Python (functions, variables), PascalCase for React components, camelCase for TypeScript functions
- **Error Handling:** Custom exception classes (`AppError`, `NotFoundError`, `AuthError`) with FastAPI exception handlers
- **Logging:** Structured logging via `structlog`, JSON format, request-id correlation
- **Input Validation:** Pydantic schemas for all API inputs, frontend uses Zod
- **Testing:** pytest with fixtures, 67% line coverage, no integration tests for payment flow

**Deviations Found:** 4 total (2 with security implications)

| File:Line | Convention | Deviation | Security Implication |
|-----------|-----------|-----------|---------------------|
| `api/routes/admin.py:45` | Custom exception classes | Uses bare `except Exception` and returns raw error | **Information disclosure** — stack traces in admin error responses |
| `workers/payment.py:112` | Structured logging | Logs raw payment response including card tokens | **Credential exposure** — PCI data in application logs |
| `api/routes/reports.py:23` | Pydantic validation | Accepts raw `dict` instead of Pydantic model | None — internal report endpoint |
| `services/email.py:67` | snake_case naming | Uses camelCase for email template variables | None — template rendering only |

---

### API Surface

| # | Method | Path | Auth | Rate Limited | Input Validated | Handler |
|---|--------|------|------|-------------|----------------|---------|
| 1 | POST | `/api/v1/auth/login` | No | Yes (5/min) | Yes | `api/routes/auth.py:15` |
| 2 | POST | `/api/v1/auth/register` | No | Yes (3/min) | Yes | `api/routes/auth.py:42` |
| 3 | POST | `/api/v1/auth/refresh` | Yes (refresh token) | Yes (10/min) | Yes | `api/routes/auth.py:78` |
| 4 | GET | `/api/v1/users/me` | Yes | No | N/A | `api/routes/users.py:12` |
| 5 | PUT | `/api/v1/users/me` | Yes | No | Yes | `api/routes/users.py:28` |
| 6 | GET | `/api/v1/users/{id}` | Yes (admin) | No | Yes | `api/routes/users.py:55` |
| 7 | DELETE | `/api/v1/users/{id}` | Yes (admin) | No | Yes | `api/routes/users.py:72` |
| 8 | GET | `/api/v1/products` | No | No | Partial | `api/routes/products.py:10` |
| 9 | POST | `/api/v1/products` | Yes (admin) | No | Yes | `api/routes/products.py:35` |
| 10 | GET | `/api/v1/products/{id}` | No | No | Yes | `api/routes/products.py:62` |
| 11 | POST | `/api/v1/orders` | Yes | No | Yes | `api/routes/orders.py:15` |
| 12 | GET | `/api/v1/orders` | Yes | No | Partial | `api/routes/orders.py:48` |
| 13 | POST | `/api/v1/payments/charge` | Yes | Yes (10/min) | Yes | `api/routes/payments.py:20` |
| 14 | POST | `/api/v1/payments/webhook` | No (signature verify) | No | Partial | `api/routes/payments.py:55` |
| 15 | GET | `/api/v1/admin/users` | Yes (admin) | No | No | `api/routes/admin.py:12` |
| ... | ... | ... | ... | ... | ... | ... |

**Total Endpoints:** 32
**Auth Coverage:** 24/32 (75%) — 8 public endpoints
**Rate Limited:** 6/32 (19%)
**Input Validated:** 26/32 (81%)

---

### Security Findings

**[CRITICAL] SQL Injection in Admin Search**

- **File:** `api/routes/admin.py:89`
- **Category:** `Database - SQL Injection`
- **Issue:** Admin user search constructs SQL query using f-string interpolation with user-supplied search parameter.
- **Impact:** Authenticated admin could exfiltrate all database data or modify records.
- **Affected Roles:** DBA, API Dev
- **Groundwork Context:** Architecture analysis identified this endpoint at a trust boundary (authenticated admin → database). The code pattern analysis flagged this file for deviating from the project's SQLAlchemy ORM convention — this is the only file using raw SQL.

**Remediation:**

**Step 1 — Immediate Fix:**
```python
# Before (vulnerable)
query = f"SELECT * FROM users WHERE email LIKE '%{search_term}%'"
result = db.execute(text(query))

# After (fixed)
query = text("SELECT * FROM users WHERE email LIKE :search")
result = db.execute(query, {"search": f"%{search_term}%"})
```

**Step 2 — Verify:**
```bash
pytest tests/test_admin.py -k "test_search_injection" -v
```
Expected: Test passes, injection payload returns empty results

**Step 3 — Prevent Recurrence:**
- Add `bandit` to CI pipeline with rule `B608` (hardcoded SQL)
- Add pre-commit hook: `bandit -r api/ -t B608`

**Step 4 — Harden Further:**
- Migrate all raw SQL to SQLAlchemy ORM queries
- Add WAF rule for SQL injection patterns on admin routes

---

**[CRITICAL] Payment Card Data in Application Logs**

- **File:** `workers/payment.py:112`
- **Category:** `Secrets - Connection String` / `Application - Credential Handling`
- **Issue:** Celery payment worker logs the full payment gateway response, which includes card tokens and partial card numbers.
- **Impact:** PCI-DSS violation. Card data exposed in log storage (CloudWatch, ELK, etc.). Any log access = card data access.
- **Affected Roles:** All
- **Groundwork Context:** Code pattern analysis detected this as a deviation from the project's structured logging convention. The project uses `structlog` with field filtering everywhere except this file.

**Remediation:**

**Step 1 — Immediate Fix:**
```python
# Before (vulnerable)
logger.info("payment_processed", response=payment_response)

# After (fixed)
logger.info("payment_processed",
    transaction_id=payment_response.get("id"),
    status=payment_response.get("status"),
    amount=payment_response.get("amount"))
```

**Step 2 — Verify:**
```bash
grep -rn "response=payment_response\|response=.*payment" workers/
```
Expected: No matches

**Step 3 — Prevent Recurrence:**
- Add log sanitization middleware that redacts fields matching `card`, `token`, `cvv`, `pan`
- Add CI check: `grep -rn "response=.*payment\|response=.*card" workers/ && exit 1`

**Step 4 — Harden Further:**
- Rotate log storage access credentials
- Enable log encryption at rest
- Audit existing logs for card data exposure and purge

---

**[HIGH] Missing Rate Limiting on 26 Endpoints**

- **File:** Multiple (see API Surface table)
- **Category:** `Performance - Missing Rate Limiting`
- **Issue:** Only 6 of 32 endpoints have rate limiting. All authenticated endpoints lack rate limiting.
- **Impact:** Credential stuffing, brute force, resource exhaustion, API abuse.
- **Affected Roles:** API Dev, DevOps
- **Groundwork Context:** API surface analysis enumerated all 32 endpoints and cross-referenced with rate limiting middleware. Without groundwork's complete endpoint discovery, a targeted scan would only catch the most obvious missing cases.

**Remediation:**

**Step 1 — Immediate Fix:**
```python
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

# Apply default limit to all routes
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/api/v1/products")
@limiter.limit("60/minute")
async def list_products():
    ...
```

**Step 2 — Verify:**
```bash
for i in $(seq 1 65); do curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/v1/products; done
```
Expected: Returns `429` after 60 requests

**Step 3 — Prevent Recurrence:**
- Add architectural test that verifies all routes have a rate limit decorator
- Document rate limit policy per endpoint tier in API docs

**Step 4 — Harden Further:**
- Add per-user rate limiting (not just per-IP)
- Configure CDN-level rate limiting as defense in depth

---

**[HIGH] BOLA on User Endpoint**

- **File:** `api/routes/users.py:55`
- **Category:** `API - Broken Object-Level Authorization (BOLA)`
- **Issue:** `GET /api/v1/users/{id}` checks for admin role but also allows any authenticated user to fetch any other user's profile by ID enumeration.
- **Impact:** Any authenticated user can enumerate and view all user profiles.
- **Affected Roles:** API Dev

**Remediation:**

**Step 1 — Immediate Fix:**
```python
# Before (vulnerable)
@router.get("/users/{user_id}")
async def get_user(user_id: int, current_user: User = Depends(get_current_user)):
    return await UserService.get_by_id(user_id)

# After (fixed)
@router.get("/users/{user_id}")
async def get_user(user_id: int, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    return await UserService.get_by_id(user_id)
```

**Step 2 — Verify:**
```bash
# As non-admin user, try to access another user's profile
curl -H "Authorization: Bearer $USER_TOKEN" http://localhost:8000/api/v1/users/999
```
Expected: Returns `403 Forbidden`

**Step 3 — Prevent Recurrence:**
- Add BOLA test case for every user-scoped endpoint
- Document authorization model (who can access what) in RBAC matrix

**Step 4 — Harden Further:**
- Switch to UUIDs instead of sequential IDs to prevent enumeration
- Add rate limiting on user lookup endpoints

---

### Documentation Correlation

| Code Module | Doc Page | Coverage | Last Code Change | Last Doc Update | Status |
|------------|----------|----------|-----------------|----------------|--------|
| `api/routes/auth.py` | `docs/authentication.md` | 3 (Full) | 2026-04-15 | 2026-04-10 | Current |
| `api/routes/payments.py` | (none) | 0 (Missing) | 2026-05-01 | — | **Gap** |
| `workers/` | (none) | 0 (Missing) | 2026-05-10 | — | **Gap** |
| `models/` | `docs/data-model.md` | 2 (Partial) | 2026-05-08 | 2026-01-15 | **Stale** |
| `auth/rbac.py` | (none) | 0 (Missing) | 2026-03-20 | — | **Gap** |

**Security Documentation Gaps:**

| Missing Document | Category | Severity |
|-----------------|----------|----------|
| Authorization model (RBAC matrix) | Auth & Authz | MEDIUM |
| Payment flow security documentation | API Security | MEDIUM |
| Incident response procedures | Operations | LOW |
| Data classification policy | Data Handling | LOW |

---

### Verification Summary

**Total Claims:** 89
**Verified:** 84 (94.4%)
**Auto-Corrected:** 3
**Unverified:** 1
**Failed:** 1

| # | Claim | Category | Source File | Status | Notes |
|---|-------|----------|-----------|--------|-------|
| 1 | Uses PostgreSQL 15 | Dependency | docker-compose.yml:12 | PASS | `image: postgres:15` confirmed |
| 2 | 32 API endpoints | Statistic | — | CORRECTED | Initial count was 34, 2 were commented out |
| 3 | structlog for logging | Dependency | requirements.txt:8 | PASS | `structlog==23.2.0` confirmed |
| 4 | No integration tests for payments | Testing | — | PASS | `find . -name "*test*payment*"` returns only unit tests |
| 5 | RabbitMQ for task queue | Architecture | — | FAIL | Actually uses Redis as Celery broker, not RabbitMQ |

---

### Security Posture

**Overall Risk:** HIGH
**Top Priority:** Fix SQL injection in admin search (CRITICAL) and remove payment card data from logs (CRITICAL)
**Quick Wins:** Add rate limiting middleware globally (1 hour), fix BOLA on user endpoint (30 min), add missing security headers (15 min)
**Architecture Notes:** The project has solid conventions (Pydantic validation, structured logging, custom exceptions) but two files deviate from these conventions, and both deviations are the source of CRITICAL findings. Enforcing convention adherence through linting would have caught both issues.
