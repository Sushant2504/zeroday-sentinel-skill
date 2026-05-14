# Sample Security Report

This is an example of the output produced by the zeroday-sentinel skill.

---

## Security Review

**Scan Date:** 2026-05-11
**Scan Mode:** Pending Changes Review
**Project Type:** Web App (API + Frontend)
**Tech Stack:** Python (FastAPI), TypeScript (React), PostgreSQL, Docker, GitHub Actions
**Scope:** 18 files changed in current branch vs main
**Files Reviewed:** 23 (4 critical, 8 high risk)
**Domains Analyzed:** Application, Web, API, Authentication, Database, Containers, CI/CD, Secrets, Performance, Critical Workflows, Git & GitHub

### Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 6 |
| MEDIUM | 5 |
| LOW | 3 |

### Findings

**[CRITICAL] Hardcoded AWS Access Key in Configuration**

- **File:** `config/settings.py:47`
- **Category:** `Secrets - Cloud Credential`
- **Issue:** AWS access key ID `AKIA3E7X...` hardcoded in source file
- **Impact:** An attacker with repository access could use these credentials to access AWS resources, potentially leading to data exfiltration or infrastructure compromise
- **Affected Roles:** All

**Remediation:**

**Step 1 — Immediate Fix:**
```python
# Before (vulnerable)
AWS_ACCESS_KEY_ID = "AKIA3E7X..."
AWS_SECRET_ACCESS_KEY = "wJalr..."

# After (fixed)
import os
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
```

**Step 2 — Verify:**
```bash
# Verify secret is not in any tracked files
git grep -i "AKIA" -- ':!*.md' ':!samples/'
```
Expected: No results returned

**Step 3 — Prevent Recurrence:**
- Install `detect-secrets`: `pip install detect-secrets && detect-secrets scan > .secrets.baseline`
- Add pre-commit hook for secret scanning
- Enable GitHub secret scanning in repository Settings → Code security

**Step 4 — Harden Further:**
- Rotate the exposed AWS credential immediately in IAM console
- Remove from git history: `git filter-repo --invert-paths --path config/settings.py`
- Migrate to AWS Secrets Manager: `boto3.client('secretsmanager').get_secret_value(SecretId='prod/aws')`
- Set up CloudTrail alerts for usage of the compromised key

---

**[CRITICAL] SQL Injection via f-string in Database Query**

- **File:** `api/routes/users.py:89`
- **Category:** `Database - SQL Injection`
- **Issue:** User-supplied `search` parameter is interpolated directly into SQL query via f-string
- **Impact:** An attacker could execute arbitrary SQL commands, exfiltrate all data, modify records, or escalate privileges within the database
- **Affected Roles:** API Dev, DBA

**Remediation:**

**Step 1 — Immediate Fix:**
```python
# Before (vulnerable)
@app.get("/users/search")
async def search_users(search: str):
    result = await db.execute(f"SELECT * FROM users WHERE name LIKE '%{search}%'")
    return result.fetchall()

# After (fixed)
@app.get("/users/search")
async def search_users(search: str):
    result = await db.execute(
        text("SELECT * FROM users WHERE name LIKE :search"),
        {"search": f"%{search}%"}
    )
    return result.fetchall()
```

**Step 2 — Verify:**
```bash
# Test with SQL injection payload
curl "http://localhost:8000/users/search?search=%27%20OR%201%3D1%3B--"
# Should return empty results or validation error, NOT all users

# Verify no f-strings remain in SQL
grep -rn 'execute.*f".*SELECT\|execute.*f".*INSERT\|execute.*f".*UPDATE\|execute.*f".*DELETE' api/
```
Expected: No results from grep

**Step 3 — Prevent Recurrence:**
- Add `bandit` to CI: `bandit -r api/ -t B608` (detects SQL injection)
- Add SQLAlchemy ORM as preferred data access layer
- Add pre-commit hook: `bandit --configfile .bandit`

**Step 4 — Harden Further:**
- Use SQLAlchemy ORM instead of raw SQL: `db.query(User).filter(User.name.ilike(f"%{search}%"))`
- Apply principle of least privilege to database user (revoke DELETE, DDL permissions)
- Add WAF rule to detect SQL injection patterns
- Enable PostgreSQL query logging in staging for audit

---

**[HIGH] Dockerfile Running as Root**

- **File:** `Dockerfile:1-28`
- **Category:** `Container - Running as Root`
- **Issue:** No `USER` instruction in Dockerfile — container runs as root by default
- **Impact:** If the container is compromised, the attacker has root access within the container, increasing the blast radius of container escape exploits
- **Affected Roles:** DevOps

**Remediation:**

**Step 1 — Immediate Fix:**
```dockerfile
# Add before ENTRYPOINT/CMD
RUN addgroup --system app && adduser --system --ingroup app app
USER app
```

**Step 2 — Verify:**
```bash
docker build -t myapp . && docker run --rm myapp whoami
```
Expected: `app` (not `root`)

**Step 3 — Prevent Recurrence:**
- Add Hadolint to CI: `hadolint Dockerfile`
- Add Trivy image scan: `trivy image --severity HIGH,CRITICAL myapp:latest`
- Enforce Pod Security Standards in Kubernetes namespace: `pod-security.kubernetes.io/enforce: restricted`

**Step 4 — Harden Further:**
- Add `readOnlyRootFilesystem: true` to Kubernetes security context
- Drop all capabilities: `capabilities: { drop: ["ALL"] }`
- Use distroless base image for minimal attack surface

---

**[HIGH] Missing Rate Limiting on Authentication Endpoints**

- **File:** `api/routes/auth.py:12-45`
- **Category:** `Performance - Missing Rate Limiting`
- **Issue:** Login (`/auth/login`) and password reset (`/auth/forgot-password`) endpoints have no rate limiting
- **Impact:** Attacker can perform brute-force password attacks or flood password reset emails, potentially compromising user accounts
- **Affected Roles:** API Dev

**Remediation:**

**Step 1 — Immediate Fix:**
```python
# Install: pip install slowapi
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, credentials: LoginRequest):
    # existing login logic...

@app.post("/auth/forgot-password")
@limiter.limit("3/minute")
async def forgot_password(request: Request, body: ForgotPasswordRequest):
    # existing logic...
```

**Step 2 — Verify:**
```bash
# Send 10 rapid login requests
for i in $(seq 1 10); do
  echo "Request $i: $(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:8000/auth/login -H 'Content-Type: application/json' -d '{"email":"test@test.com","password":"wrong"}')"
done
```
Expected: First 5 return 401 (wrong password), remaining return 429 (too many requests)

**Step 3 — Prevent Recurrence:**
- Add integration test that verifies rate limiting on all auth endpoints
- Add API gateway-level rate limiting as first line of defense

**Step 4 — Harden Further:**
- Implement exponential backoff after consecutive failures (1s, 2s, 4s, 8s...)
- Add CAPTCHA after 3 failed login attempts
- Log all failed login attempts with IP and user agent for anomaly detection
- Set up alerts for spikes in auth failures

---

**[HIGH] XSS via dangerouslySetInnerHTML with User Content**

- **File:** `frontend/src/components/UserBio.tsx:24`
- **Category:** `Web - Cross-Site Scripting (XSS)`
- **Issue:** User-supplied bio HTML rendered via `dangerouslySetInnerHTML` without sanitization
- **Impact:** Attacker could inject malicious JavaScript that steals session cookies, redirects users, or performs actions on behalf of the victim
- **Affected Roles:** Web Dev

**Remediation:**

**Step 1 — Immediate Fix:**
```tsx
// Install: npm install dompurify @types/dompurify

// Before (vulnerable)
<div dangerouslySetInnerHTML={{__html: user.bio}} />

// After (fixed)
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(user.bio)}} />
```

**Step 2 — Verify:**
```bash
# Set user bio to XSS payload and check rendered output
# bio = '<img src=x onerror=alert(document.cookie)>'
# Should render as <img src="x"> (onerror stripped by DOMPurify)
```
Expected: No JavaScript execution when viewing the user profile

**Step 3 — Prevent Recurrence:**
- Add ESLint rule: `eslint-plugin-no-unsanitized` → `no-unsanitized/property: error`
- Add Content-Security-Policy header: `script-src 'self'` (blocks inline scripts)

**Step 4 — Harden Further:**
- Consider using Markdown instead of raw HTML for user bios
- Add CSP with nonce-based script loading
- Add `X-Content-Type-Options: nosniff` header

---

**[HIGH] Missing CORS Origin Validation**

- **File:** `api/main.py:15`
- **Category:** `Web - CORS Misconfiguration`
- **Issue:** CORS configured with `allow_origins=["*"]` while also using `allow_credentials=True`
- **Impact:** Any website can make authenticated cross-origin requests to the API, enabling cross-site data theft
- **Affected Roles:** API Dev, Web Dev

**Remediation:**

**Step 1 — Immediate Fix:**
```python
# Before (vulnerable)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)

# After (fixed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com", "https://admin.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

**Step 2 — Verify:**
```bash
# Test with unauthorized origin
curl -H "Origin: https://evil.com" -I http://localhost:8000/api/users
# Should NOT contain Access-Control-Allow-Origin: https://evil.com
```
Expected: No CORS headers returned for unauthorized origins

**Step 3 — Prevent Recurrence:**
- Add integration test that verifies CORS rejects unauthorized origins
- Document allowed origins in CLAUDE.md or deployment configuration

**Step 4 — Harden Further:**
- Use environment variable for allowed origins: `CORS_ORIGINS=https://app.example.com,https://admin.example.com`
- Set `max_age=86400` to cache preflight responses

---

**[MEDIUM] Missing Content-Security-Policy Header**

- **File:** `api/main.py` (global middleware)
- **Category:** `Web - Missing Security Headers`
- **Issue:** No Content-Security-Policy header configured, allowing unrestricted script sources
- **Impact:** Reduces defense against XSS attacks — injected scripts can load from any origin
- **Affected Roles:** Web Dev, DevOps

**Remediation:**

**Step 1 — Immediate Fix:**
```python
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.example.com; frame-ancestors 'none'; base-uri 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

**Step 2 — Verify:**
```bash
curl -sI http://localhost:8000/ | grep -i "content-security-policy"
```
Expected: CSP header present with restrictive policy

**Step 3 — Prevent Recurrence:**
- Add security header scan to CI: use `securityheaders.com` API or `observatory.mozilla.org`
- Test CSP in report-only mode first: `Content-Security-Policy-Report-Only`

**Step 4 — Harden Further:**
- Implement nonce-based CSP for scripts
- Add `Permissions-Policy: camera=(), microphone=(), geolocation=()`

---

**[MEDIUM] Unpinned GitHub Action**

- **File:** `.github/workflows/ci.yml:22`
- **Category:** `CI/CD - Action Pinning`
- **Issue:** Action `uses: actions/setup-python@v5` is pinned to a tag, not a SHA hash
- **Impact:** The action author could push malicious code to the v5 tag, which would execute in your CI pipeline
- **Affected Roles:** DevOps

**Remediation:**

**Step 1 — Immediate Fix:**
```yaml
# Before (vulnerable)
- uses: actions/setup-python@v5

# After (fixed)
- uses: actions/setup-python@f677139bbe7f9c59b41e40162b753c062f5d49a3 # v5.3.0
```

**Step 2 — Verify:**
```bash
grep -r "uses:" .github/workflows/ | grep -v "@[a-f0-9]\{40\}"
```
Expected: No results (all actions SHA-pinned)

**Step 3 — Prevent Recurrence:**
- Use `pinact` to auto-pin: `npx pinact .github/workflows/*.yml`
- Enable Dependabot for GitHub Actions updates

**Step 4 — Harden Further:**
- Review action source code before pinning new third-party actions
- Consider using organization-level action allowlists

---

**[MEDIUM] Missing Database Query Pagination**

- **File:** `api/routes/orders.py:34`
- **Category:** `Performance - Unbounded Query Results`
- **Issue:** `GET /orders` returns all orders without pagination, potentially returning millions of rows
- **Impact:** Can cause memory exhaustion (DoS) and expose excessive data
- **Affected Roles:** API Dev, DBA

**Remediation:**

**Step 1 — Immediate Fix:**
```python
# Before (vulnerable)
@app.get("/orders")
async def list_orders():
    return await db.fetch_all("SELECT * FROM orders")

# After (fixed)
@app.get("/orders")
async def list_orders(page: int = 1, per_page: int = 20):
    per_page = min(per_page, 100)  # cap maximum
    offset = (page - 1) * per_page
    orders = await db.fetch_all(
        text("SELECT * FROM orders ORDER BY created_at DESC LIMIT :limit OFFSET :offset"),
        {"limit": per_page, "offset": offset}
    )
    total = await db.fetch_val("SELECT COUNT(*) FROM orders")
    return {"data": orders, "page": page, "per_page": per_page, "total": total}
```

**Step 2 — Verify:**
```bash
curl "http://localhost:8000/orders" | python -c "import sys,json; d=json.load(sys.stdin); assert len(d['data']) <= 20"
curl "http://localhost:8000/orders?per_page=10000" | python -c "import sys,json; d=json.load(sys.stdin); assert len(d['data']) <= 100"
```
Expected: Results capped at page size

**Step 3 — Prevent Recurrence:**
- Add linting rule to flag `SELECT` without `LIMIT` in query strings
- Set database-level `statement_timeout = '30s'`

**Step 4 — Harden Further:**
- Consider cursor-based pagination for large datasets
- Add caching for frequently accessed list endpoints

---

**[LOW] Missing HEALTHCHECK in Dockerfile**

- **File:** `Dockerfile:28`
- **Category:** `Container - Unpinned Base Image`
- **Issue:** No `HEALTHCHECK` instruction defined
- **Impact:** Container orchestrators cannot detect unhealthy containers for automatic restart
- **Affected Roles:** DevOps

**Remediation:**

**Step 1 — Immediate Fix:**
```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1
```

**Step 2 — Verify:**
```bash
docker inspect --format='{{json .Config.Healthcheck}}' myapp | python -m json.tool
```
Expected: Healthcheck configuration present

---

**[LOW] Verbose Error Messages in API**

- **File:** `api/main.py:55`
- **Category:** `Application - Error Handling`
- **Issue:** Unhandled exception returns stack trace and internal paths in production error responses
- **Impact:** Exposes internal code structure, library versions, and potentially sensitive variable values
- **Affected Roles:** API Dev

**Remediation:**

**Step 1 — Immediate Fix:**
```python
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error", exc_info=exc, path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "request_id": request.state.request_id},
    )
```

**Step 2 — Verify:**
```bash
curl http://localhost:8000/api/trigger-error
# Should return generic error, NOT stack trace
```
Expected: `{"error": "Internal server error", "request_id": "..."}`

---

**[HIGH] Feature Flag Gating Authentication Check**

- **File:** `api/middleware/feature_gate.py:23`
- **Category:** `Feature Flag - Security Gate`
- **Issue:** Authentication middleware is conditionally applied based on feature flag `new-auth-flow`. When the flag is off, requests bypass authentication entirely
- **Impact:** If the flag is disabled (maintenance, flag service outage, or misconfiguration), all protected endpoints become publicly accessible
- **Affected Roles:** API Dev, DevOps

**Remediation:**

**Step 1 — Immediate Fix:**
```python
# Before (vulnerable) — auth skipped when flag is off
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if feature_flags.is_enabled("new-auth-flow"):
        await verify_token(request)
    response = await call_next(request)
    return response

# After (fixed) — auth is unconditional, only implementation varies
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path not in PUBLIC_PATHS:
        await verify_token(request)  # always runs
    response = await call_next(request)
    return response
```

**Step 2 — Verify:**
```bash
# Disable the feature flag, then test protected endpoint
curl -X GET http://localhost:8000/api/users -H "Authorization: Bearer valid-token"
# Should return 200

curl -X GET http://localhost:8000/api/users
# Should return 401 regardless of flag state
```
Expected: 401 Unauthorized when no token provided, regardless of feature flag state

**Step 3 — Prevent Recurrence:**
- Add linting rule to detect feature flags near auth/security code
- Establish team policy: security checks must never be behind feature flags

**Step 4 — Harden Further:**
- Implement quarterly feature flag audit to remove stale flags
- Tag security-relevant flags with metadata for automated review

---

**[MEDIUM] Database Migration Without Rollback Path**

- **File:** `migrations/0015_add_user_roles.sql:1`
- **Category:** `Rollback - No Down Migration`
- **Issue:** Migration adds `ALTER TABLE users ADD COLUMN role` and `DROP TABLE legacy_permissions` but provides no DOWN migration. The `DROP TABLE` is destructive and irreversible
- **Impact:** If the migration causes issues in production, there is no automated rollback path. The dropped table's data is permanently lost
- **Affected Roles:** DBA, DevOps

**Remediation:**

**Step 1 — Immediate Fix:**
```sql
-- Add DOWN migration
-- DOWN:
CREATE TABLE IF NOT EXISTS legacy_permissions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    permission VARCHAR(100)
);
ALTER TABLE users DROP COLUMN IF EXISTS role;

-- Better approach: split into 3 phases
-- Phase 1 (this PR): Add new column, copy data
-- Phase 2 (after verification): Update app code to use new column
-- Phase 3 (separate PR): Drop legacy table after Phase 2 is stable
```

**Step 2 — Verify:**
```bash
# Test migration round-trip in staging
python manage.py migrate myapp 0015  # forward
python manage.py migrate myapp 0014  # rollback
python manage.py migrate myapp 0015  # forward again
```
Expected: All three steps succeed without errors, data integrity maintained

**Step 3 — Prevent Recurrence:**
- Add CI check requiring every UP migration to have a corresponding DOWN migration
- Block `DROP TABLE` in migrations without team lead approval

**Step 4 — Harden Further:**
- Use expand-contract pattern for all destructive schema changes
- Require staging deployment with rollback test before production migration

---

**[LOW] Hotfix Branch Not Merged Back to Develop**

- **File:** `(branch: hotfix/fix-payment-timeout)`
- **Category:** `Hotfix - Missing Review`
- **Issue:** Hotfix branch `hotfix/fix-payment-timeout` was merged to main 5 days ago but has not been merged back to develop. The fix is missing from the development branch
- **Impact:** The fix will be lost in the next release cut from develop, potentially reintroducing the payment timeout bug
- **Affected Roles:** DevOps, All

**Remediation:**

**Step 1 — Immediate Fix:**
```bash
git checkout develop
git merge hotfix/fix-payment-timeout
git push origin develop
git branch -d hotfix/fix-payment-timeout
```

**Step 2 — Verify:**
```bash
git log develop --oneline | head -5
# Should contain the hotfix commit
```
Expected: Hotfix commit visible in develop branch history

**Step 3 — Prevent Recurrence:**
- Enable auto-delete for merged branches in GitHub repo settings
- Add CI check that verifies hotfix branches are merged to all active branches

**Step 4 — Harden Further:**
- Use GitHub branch protection rules to require hotfix merge-back
- Set up Slack/email notification when hotfix branches are stale >24h

---

**[HIGH] No Branch Protection on Main Branch**

- **File:** `(repository settings)`
- **Category:** `GitHub - Branch Protection Gap`
- **Issue:** The `main` branch has no branch protection rules enabled. Direct pushes, force pushes, and merges without review are all permitted
- **Impact:** Any contributor can push directly to main, bypassing code review and CI checks. A compromised account or malicious insider could push backdoored code without oversight
- **Affected Roles:** DevOps, All

**Remediation:**

**Step 1 — Immediate Fix:**
```bash
gh api repos/{owner}/{repo}/branches/main/protection -X PUT \
  -f "required_pull_request_reviews[required_approving_review_count]=1" \
  -f "required_pull_request_reviews[dismiss_stale_reviews]=true" \
  -f "required_status_checks[strict]=true" \
  -f "required_status_checks[contexts][]=ci/tests" \
  -f "enforce_admins=true" \
  -f "allow_force_pushes=false" \
  -f "allow_deletions=false"
```

**Step 2 — Verify:**
```bash
gh api repos/{owner}/{repo}/branches/main/protection --jq '.enforce_admins.enabled'
# Should return: true
```
Expected: Branch protection enforced, direct pushes blocked

**Step 3 — Prevent Recurrence:**
- Add CODEOWNERS file for security-critical paths
- Enable `Require review from Code Owners`

**Step 4 — Harden Further:**
- Require signed commits on main
- Add required status checks for security scanning

---

**[MEDIUM] Git Credential Helper Using Plaintext Storage**

- **File:** `.gitconfig:3`
- **Category:** `Git - Credential Storage`
- **Issue:** Git credential helper is set to `store`, which saves credentials in plaintext at `~/.git-credentials`
- **Impact:** Any process or user with file system access can read GitHub credentials (PATs, passwords) in plaintext
- **Affected Roles:** All

**Remediation:**

**Step 1 — Immediate Fix:**
```bash
# Switch to secure credential helper
git config --global credential.helper osxkeychain  # macOS
# OR
git config --global credential.helper libsecret    # Linux

# Delete the plaintext credential file
rm ~/.git-credentials
```

**Step 2 — Verify:**
```bash
git config --global credential.helper
# Should NOT return "store"

ls -la ~/.git-credentials 2>/dev/null
# Should return "No such file or directory"
```
Expected: Secure credential helper configured, no plaintext credential file

**Step 3 — Prevent Recurrence:**
- Add credential helper check to team onboarding scripts
- Document secure git setup in team playbook

**Step 4 — Harden Further:**
- Rotate any credentials that were stored in plaintext
- Use SSH authentication instead of HTTPS with PATs

---

### Domains Not Analyzed

- **Infrastructure/IaC**: No Terraform or ArgoCD files detected
- **Agent/Skill**: No SKILL.md or agent definition files detected
- **Mobile**: No mobile source files detected
- **Cloud Native**: No cloud SDK usage detected (AWS/GCP/Azure)

### Security Posture

**Overall Risk:** HIGH
**Top Priority:** Rotate the exposed AWS credentials immediately and fix the SQL injection
**Quick Wins:** Add CSP header (1 middleware function), pin GitHub Actions (use `pinact`), add rate limiting (1 dependency + 3 decorators)
**Architecture Notes:** The application lacks a consistent security middleware layer. Consider creating a centralized security middleware that handles: auth, rate limiting, CORS, security headers, and request validation. This would prevent similar gaps as new endpoints are added.

### Notes

- The `slowapi` rate limiter uses in-memory storage by default. For multi-instance deployments, configure Redis-backed storage.
- Supply chain threat intelligence search returned no known compromises for any of the changed dependencies.
- Consider adding `helmet` equivalent security headers middleware to standardize header management.
