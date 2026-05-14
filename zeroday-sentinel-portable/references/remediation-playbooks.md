# Remediation Playbooks

Step-by-step remediation instructions for every finding category. Each playbook includes immediate fix, verification, prevention, and hardening steps.

## How to Use This Document

When a finding is reported, locate its category below and follow the 4-step playbook:
1. **Immediate Fix** — code-level change to resolve the vulnerability
2. **Verify** — confirm the fix works and the vulnerability is gone
3. **Prevent** — add automation to catch this in the future
4. **Harden** — additional defense-in-depth measures

---

## Secrets & Credentials

### Playbook: Hardcoded Secret Found

**Step 1 — Immediate Fix:**
1. Remove the secret from source code
2. Move to environment variable or secret manager
3. Update application to read from new location

```bash
# Move to environment variable
export DATABASE_URL="postgres://user:pass@host/db"

# Or use a .env file (add to .gitignore first!)
echo ".env" >> .gitignore
echo 'DATABASE_URL=postgres://user:pass@host/db' > .env
```

**Step 2 — Verify:**
```bash
# Verify secret is not in any tracked files
git grep -i "AKIA\|password\s*=\s*['\"]" -- ':!*.md'

# Verify application still works with env var
env | grep DATABASE_URL && npm start
```

**Step 3 — Prevent:**
```bash
# Install git-secrets
git secrets --install
git secrets --register-aws

# Or use pre-commit with detect-secrets
# .pre-commit-config.yaml
# - repo: https://github.com/Yelp/detect-secrets
#   rev: v1.4.0
#   hooks:
#     - id: detect-secrets
#       args: ['--baseline', '.secrets.baseline']

# Generate baseline
detect-secrets scan > .secrets.baseline
```

**Step 4 — Harden:**
1. Rotate the exposed credential immediately
2. Remove from git history: `git filter-repo --invert-paths --path <file-with-secret>`
3. Set up secret scanning in GitHub (Settings → Code security → Secret scanning)
4. Use a secret manager (AWS Secrets Manager, HashiCorp Vault, 1Password CLI)

### Playbook: Secret in Git History

**Step 1 — Immediate Fix:**
```bash
# Option A: BFG Repo-Cleaner (faster, simpler)
bfg --replace-text passwords.txt repo.git

# Option B: git filter-repo (more flexible)
git filter-repo --invert-paths --path secrets.env

# Option C: For a single string
git filter-repo --blob-callback '
  return blob.data.replace(b"AKIA...", b"REDACTED")
'
```

**Step 2 — Verify:**
```bash
# Verify secret is gone from all history
git log --all -p | grep -c "AKIA"  # should be 0

# Force push (coordinate with team)
git push --force-with-lease --all
```

**Step 3 — Prevent:** Same as "Hardcoded Secret Found" above.

**Step 4 — Harden:**
1. Rotate the credential — assume it was compromised
2. Audit access logs for the compromised credential
3. Notify affected team members to re-clone the repository

---

## Injection Vulnerabilities

### Playbook: SQL Injection

**Step 1 — Immediate Fix:**
Replace string interpolation with parameterized queries.

```python
# Before (VULNERABLE)
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# After (FIXED)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```javascript
// Before (VULNERABLE)
db.query(`SELECT * FROM users WHERE id = ${userId}`);

// After (FIXED)
db.query('SELECT * FROM users WHERE id = $1', [userId]);
```

```go
// Before (VULNERABLE)
db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID))

// After (FIXED)
db.Query("SELECT * FROM users WHERE id = $1", userID)
```

**Step 2 — Verify:**
```bash
# Test with SQL injection payload
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"id": "1 OR 1=1; DROP TABLE users;--"}'
# Should return error or empty result, NOT all users

# Run sqlmap (if authorized for testing)
# sqlmap -u "http://localhost:3000/api/users?id=1" --batch --level=3
```

**Step 3 — Prevent:**
```yaml
# ESLint rule (eslint-plugin-security)
rules:
  security/detect-sql-injection: error

# Python: bandit
# bandit -r . -t B608  # hardcoded SQL expressions

# Go: gosec
# gosec -include=G201,G202 ./...
```

**Step 4 — Harden:**
1. Use an ORM (SQLAlchemy, Prisma, GORM) as the default data access layer
2. Enable database query logging in staging for audit
3. Apply principle of least privilege to database user
4. Use a WAF rule to detect SQL injection patterns

### Playbook: XSS (Cross-Site Scripting)

**Step 1 — Immediate Fix:**
```javascript
// Before (VULNERABLE)
element.innerHTML = userInput;

// After (FIXED) — Option A: Use textContent
element.textContent = userInput;

// After (FIXED) — Option B: Sanitize with DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

```jsx
// React: Before (VULNERABLE)
<div dangerouslySetInnerHTML={{__html: userContent}} />

// React: After (FIXED)
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userContent)}} />

// React: Best — avoid dangerouslySetInnerHTML entirely
<div>{userContent}</div>
```

**Step 2 — Verify:**
```bash
# Test with XSS payloads
curl "http://localhost:3000/search?q=<script>alert(1)</script>"
# Should see escaped output, NOT rendered script tag

# Test common bypasses
curl "http://localhost:3000/search?q=<img src=x onerror=alert(1)>"
curl "http://localhost:3000/search?q=<svg onload=alert(1)>"
```

**Step 3 — Prevent:**
```
# Add Content-Security-Policy header
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'

# ESLint: ban dangerous DOM APIs
# eslint-plugin-no-unsanitized
rules:
  no-unsanitized/property: error
  no-unsanitized/method: error
```

**Step 4 — Harden:**
1. Implement CSP with nonce-based script loading
2. Set `X-Content-Type-Options: nosniff`
3. Use auto-escaping template engine (React, Vue, Angular do this by default)
4. Add XSS detection in WAF

### Playbook: Command Injection

**Step 1 — Immediate Fix:**
```python
# Before (VULNERABLE)
os.system(f"convert {filename} output.png")

# After (FIXED) — use subprocess with list args
import subprocess
import shlex
subprocess.run(["convert", filename, "output.png"], check=True)
# OR for controlled input:
subprocess.run(["convert", shlex.quote(filename), "output.png"], shell=True, check=True)
```

```javascript
// Before (VULNERABLE)
exec(`convert ${filename} output.png`);

// After (FIXED) — use execFile with array args
const { execFile } = require('child_process');
execFile('convert', [filename, 'output.png'], (err, stdout) => { ... });
```

**Step 2 — Verify:**
```bash
# Test with injection payload
curl -X POST http://localhost:3000/convert \
  -d '{"filename": "test.jpg; rm -rf /"}'
# Should fail safely, not execute the injected command
```

**Step 3 — Prevent:**
```bash
# Python: bandit
bandit -r . -t B602,B603,B604,B605,B607

# Node.js: eslint-plugin-security
# rules: security/detect-child-process: error

# Go: gosec
# gosec -include=G204 ./...
```

**Step 4 — Harden:**
1. Use allowlists for expected input values
2. Run command-executing code in sandboxed environment
3. Use AppArmor/SELinux profiles to restrict process capabilities
4. Never run application processes as root

---

## Authentication & Authorization

### Playbook: Missing Authentication

**Step 1 — Immediate Fix:**
```javascript
// Express.js — Add global auth middleware
const authMiddleware = require('./middleware/auth');

// Apply to all routes by default
app.use(authMiddleware);

// Explicitly skip for public routes
const publicRoutes = ['/health', '/auth/login', '/auth/register'];
function authMiddleware(req, res, next) {
  if (publicRoutes.includes(req.path)) return next();
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = verifyToken(token);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}
```

**Step 2 — Verify:**
```bash
# Test unauthenticated access
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/users
# Should return 401

# Test authenticated access
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/users
# Should return 200
```

**Step 3 — Prevent:**
- Add integration tests that verify all endpoints require auth
- Use a security linting rule that checks for auth middleware on routes

**Step 4 — Harden:**
1. Implement rate limiting on all endpoints
2. Add request logging with user identity
3. Set up alerts for unusual access patterns

### Playbook: IDOR / Broken Object-Level Authorization

**Step 1 — Immediate Fix:**
```python
# Before (VULNERABLE)
@app.get("/orders/{order_id}")
def get_order(order_id: int):
    return db.get(Order, order_id)

# After (FIXED)
@app.get("/orders/{order_id}")
def get_order(order_id: int, user: User = Depends(get_current_user)):
    order = db.query(Order).filter(
        Order.id == order_id,
        Order.user_id == user.id  # ownership check
    ).first()
    if not order:
        raise HTTPException(status_code=404)
    return order
```

**Step 2 — Verify:**
```bash
# Log in as User A, try to access User B's resource
TOKEN_A=$(login_as user_a)
TOKEN_B=$(login_as user_b)
ORDER_B=$(create_order_as user_b)

curl -H "Authorization: Bearer $TOKEN_A" \
  http://localhost:3000/api/orders/$ORDER_B
# Should return 404, NOT the order
```

**Step 3 — Prevent:**
- Write authorization tests for every endpoint that accesses user-specific data
- Use ORM scopes/middleware that automatically filter by current user

**Step 4 — Harden:**
1. Use UUIDs instead of sequential IDs (harder to enumerate)
2. Add rate limiting to prevent enumeration attacks
3. Log authorization failures for anomaly detection

---

## Performance & DoS Prevention

### Playbook: Missing Rate Limiting

**Step 1 — Immediate Fix:**
```javascript
// Express.js
const rateLimit = require('express-rate-limit');

// Global rate limit
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                  // per IP
  standardHeaders: true,
  legacyHeaders: false,
}));

// Strict rate limit for auth
app.use('/api/auth', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
}));
```

```python
# FastAPI
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/auth/login")
@limiter.limit("5/minute")
async def login(request: Request): ...
```

**Step 2 — Verify:**
```bash
# Send requests rapidly
for i in $(seq 1 20); do
  echo "Request $i: $(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/api/auth/login -d '{}')"
done
# Should start returning 429 after the limit
```

**Step 3 — Prevent:**
- Add rate limiting to your API gateway/load balancer as first line of defense
- Include rate limit tests in your test suite

**Step 4 — Harden:**
1. Use distributed rate limiting (Redis-backed) for multi-instance deployments
2. Implement bot detection (CAPTCHA, device fingerprinting)
3. Set up DDoS protection (CloudFlare, AWS Shield, Cloud Armor)
4. Add alerts for rate limit spikes

### Playbook: Unbounded Query Results

**Step 1 — Immediate Fix:**
```python
# Before (VULNERABLE)
@app.get("/users")
def list_users():
    return db.query(User).all()

# After (FIXED)
@app.get("/users")
def list_users(page: int = 1, per_page: int = 20):
    per_page = min(per_page, 100)  # cap maximum
    offset = (page - 1) * per_page
    users = db.query(User).offset(offset).limit(per_page).all()
    total = db.query(User).count()
    return {"data": users, "page": page, "per_page": per_page, "total": total}
```

**Step 2 — Verify:**
```bash
# Request without limit should return paginated results
curl "http://localhost:3000/api/users"
# Should return max 20 results with pagination metadata

# Request with excessive limit should be capped
curl "http://localhost:3000/api/users?per_page=10000"
# Should return max 100 results
```

**Step 3 — Prevent:**
- Add a linting rule that flags `SELECT` without `LIMIT` or ORM queries without `.limit()`
- Add database-level statement timeout

**Step 4 — Harden:**
1. Implement cursor-based pagination for large datasets
2. Add query timeout at database level
3. Monitor slow queries and set up alerts

---

## Infrastructure & Configuration

### Playbook: Overly Permissive IAM

**Step 1 — Immediate Fix:**
```hcl
# Before (VULNERABLE)
resource "aws_iam_policy" "app" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# After (FIXED)
resource "aws_iam_policy" "app" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::my-bucket/uploads/*"
    }]
  })
}
```

**Step 2 — Verify:**
```bash
# Use IAM Policy Simulator
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123:role/app-role \
  --action-names "s3:DeleteBucket" "ec2:TerminateInstances"
# Should show "implicitDeny" for actions not needed

# Use IAM Access Analyzer
aws accessanalyzer create-analyzer --analyzer-name check --type ACCOUNT
```

**Step 3 — Prevent:**
```bash
# tfsec / trivy for Terraform scanning
trivy config --severity HIGH,CRITICAL .

# checkov for IaC scanning
checkov -d . --framework terraform

# Add to CI pipeline
```

**Step 4 — Harden:**
1. Enable AWS CloudTrail for all API calls
2. Use IAM Access Analyzer to identify unused permissions
3. Implement permission boundaries for all roles
4. Review IAM policies quarterly

### Playbook: Container Running as Root

**Step 1 — Immediate Fix:**
```dockerfile
# Before (VULNERABLE)
FROM node:20
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]

# After (FIXED)
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --production

FROM node:20-slim
RUN addgroup --system app && adduser --system --ingroup app app
WORKDIR /app
COPY --from=build --chown=app:app /app/node_modules ./node_modules
COPY --chown=app:app . .
USER app
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:3000/health || exit 1
CMD ["node", "server.js"]
```

**Step 2 — Verify:**
```bash
# Build and check the running user
docker build -t myapp .
docker run --rm myapp whoami
# Should print "app", NOT "root"

# Check with trivy
trivy image myapp --severity HIGH,CRITICAL
```

**Step 3 — Prevent:**
```yaml
# Kubernetes admission policy (Pod Security Standards)
apiVersion: v1
kind: Namespace
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

**Step 4 — Harden:**
1. Use distroless or scratch base images
2. Enable read-only root filesystem
3. Drop all capabilities and add only needed ones
4. Scan images in CI before pushing to registry

---

## CI/CD Pipeline

### Playbook: GitHub Actions Script Injection

**Step 1 — Immediate Fix:**
```yaml
# Before (VULNERABLE)
- run: echo "Processing PR: ${{ github.event.pull_request.title }}"

# After (FIXED) — use environment variable
- run: echo "Processing PR: $PR_TITLE"
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
```

**Step 2 — Verify:**
- Create a test PR with title: `"; curl evil.com; echo "`
- Verify the workflow logs show the literal string, not command execution

**Step 3 — Prevent:**
```bash
# Use actionlint
actionlint .github/workflows/*.yml
# Detects expression injection in run: steps

# Add to CI
- uses: reviewdog/action-actionlint@v1
```

**Step 4 — Harden:**
1. Set explicit workflow permissions: `permissions: read-all`
2. Pin all actions to SHA hashes
3. Use environments with required reviewers for deployment workflows
4. Enable GitHub Advanced Security for secret scanning and code scanning

### Playbook: Unpinned GitHub Actions

**Step 1 — Immediate Fix:**
```yaml
# Before (VULNERABLE)
- uses: actions/checkout@v4

# After (FIXED) — find the SHA for the tag
# git ls-remote --tags https://github.com/actions/checkout | grep v4
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

**Step 2 — Verify:**
```bash
# Check all actions are SHA-pinned
grep -r "uses:" .github/workflows/ | grep -v "@[a-f0-9]\{40\}"
# Should return empty (no unpinned actions)
```

**Step 3 — Prevent:**
```bash
# Use pinact to auto-pin actions
npx pinact .github/workflows/*.yml

# Use Renovate/Dependabot to keep SHA pins updated
# renovate.json: { "github-actions": { "enabled": true } }
```

**Step 4 — Harden:**
1. Enable GitHub Dependabot for action version updates
2. Review action source code before pinning new actions
3. Use organization-level action allow lists
4. Verify action maintainer identity and repository activity

---

## Data Protection

### Playbook: PII in Logs/Exports

**Step 1 — Immediate Fix:**
```python
# Before (VULNERABLE)
logger.info(f"User login: {user.email}, password: {user.password}")

# After (FIXED) — structured logging with redaction
import structlog

REDACT_FIELDS = {'password', 'ssn', 'credit_card', 'token', 'secret'}

def redact_processor(logger, method_name, event_dict):
    for key in REDACT_FIELDS:
        if key in event_dict:
            event_dict[key] = '***REDACTED***'
    return event_dict

structlog.configure(processors=[redact_processor, structlog.dev.ConsoleRenderer()])
logger = structlog.get_logger()
logger.info("user_login", email=user.email, password=user.password)
# Output: user_login email=user@example.com password=***REDACTED***
```

**Step 2 — Verify:**
```bash
# Search logs for PII patterns
grep -rE "(password|ssn|credit.?card|secret)\s*[:=]" logs/ | grep -v REDACTED
# Should return empty
```

**Step 3 — Prevent:**
- Add log sanitization as middleware (runs on every log entry)
- Add CI check that scans for PII patterns in log statements

**Step 4 — Harden:**
1. Implement data classification (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)
2. Add access controls to log storage (restrict who can view logs)
3. Set log retention policies (delete after 90 days unless required for compliance)
4. Encrypt logs at rest

### Playbook: CSV/Excel Injection in Exports

**Step 1 — Immediate Fix:**
```python
def sanitize_csv_value(value):
    """Prevent formula injection in exported CSV/Excel files."""
    if isinstance(value, str) and value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
        return f"'{value}"
    return value

# Apply to all exported data
safe_data = [{k: sanitize_csv_value(v) for k, v in row.items()} for row in data]
```

```javascript
function sanitizeCsvValue(value) {
  if (typeof value === 'string' && /^[=+\-@\t\r]/.test(value)) {
    return `'${value}`;
  }
  return value;
}
```

**Step 2 — Verify:**
- Export data containing `=HYPERLINK("http://evil.com","Click")` as a cell value
- Open in Excel and verify it appears as text, not a clickable hyperlink

**Step 3 — Prevent:**
- Add sanitization to your CSV/Excel export utility as a standard step
- Add unit tests with injection payloads

**Step 4 — Harden:**
1. Add `Content-Disposition: attachment` header on download endpoints
2. Consider using PDF for sensitive exports (no formula execution)
3. Add export audit logging (who exported what, when)

---

## Critical Workflows

### Playbook: Debug Build Shipped to App Store

**Step 1 — Immediate Fix:**
1. Immediately halt the rollout (Google Play: pause staged rollout; App Store: remove from sale if possible)
2. Rebuild with correct release configuration
3. Verify signing, minification, and debug flags

```kotlin
// build.gradle.kts — verify release config
android {
    buildTypes {
        release {
            isDebuggable = false        // MUST be false
            isMinifyEnabled = true      // MUST be true
            isShrinkResources = true    // MUST be true
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
```

```bash
# Verify APK is not debuggable
aapt dump badging app-release.apk | grep -i "debuggable"
# Should output nothing (no debuggable flag)
```

**Step 2 — Verify:**
```bash
# Android: verify release APK
aapt dump badging app-release.apk | grep -c "debuggable" # should be 0
apksigner verify --print-certs app-release.apk # verify release signing

# iOS: verify archive
xcodebuild -showBuildSettings -scheme YourApp -configuration Release | grep -i "debug"
```

**Step 3 — Prevent:**
```bash
# Add CI check before upload
#!/bin/bash
set -euo pipefail
if aapt dump badging "$1" | grep -q "debuggable"; then
  echo "ERROR: Debug build detected. Aborting upload."
  exit 1
fi
if ! grep -q "isMinifyEnabled = true" app/build.gradle.kts; then
  echo "ERROR: Minification not enabled for release."
  exit 1
fi
```

**Step 4 — Harden:**
1. Add pre-upload validation in CI pipeline (Fastlane lane or GitHub Actions step)
2. Use separate build configurations for debug/release with no overlap
3. Implement app attestation (Play Integrity / App Attest) to detect tampered builds
4. Add monitoring for unusual debug-related crash patterns in production

---

### Playbook: Merge Conflict Dropped Security Check

**Step 1 — Immediate Fix:**
1. Identify which security check was lost by comparing against both parent branches
2. Restore the missing validation/auth/sanitization code
3. Verify the merged logic is correct end-to-end

```bash
# Find what was lost: compare merged result against both parents
git diff HEAD~1...HEAD -- src/middleware/auth.js
git log --merge -- src/middleware/auth.js

# Compare the merged file against each parent
git show HEAD~1:src/middleware/auth.js > /tmp/ours.js
git show MERGE_HEAD:src/middleware/auth.js > /tmp/theirs.js 2>/dev/null
diff /tmp/ours.js src/middleware/auth.js  # what changed from our version
```

**Step 2 — Verify:**
```bash
# Run auth/security-specific tests
npm test -- --grep "auth\|security\|permission\|validation"

# Verify auth middleware is applied to all protected routes
grep -rn "router\.\(get\|post\|put\|delete\)" src/routes/ | grep -v "authMiddleware\|isAuthenticated\|requireAuth"
```
Expected: all non-public routes should have auth middleware applied.

**Step 3 — Prevent:**
- Add CODEOWNERS for security-critical files requiring security team review
- Add CI check that verifies auth middleware coverage on all routes
- Use `git rerere` cautiously — never auto-resolve conflicts in auth files

```
# .github/CODEOWNERS
/src/middleware/auth* @security-team
/src/middleware/permission* @security-team
/src/config/cors* @security-team
/src/config/csp* @security-team
```

**Step 4 — Harden:**
1. Add integration tests that verify auth on every endpoint
2. Add a "security regression" test suite that runs post-merge
3. Consider architectural patterns that make auth harder to accidentally remove (global middleware vs per-route)

---

### Playbook: Hotfix Bypassed CI

**Step 1 — Immediate Fix:**
1. Run the CI pipeline retroactively on the deployed commit
2. If CI would have failed, assess the severity and decide on immediate rollback vs forward-fix
3. Document what was skipped and why

```bash
# Run CI checks retroactively on the deployed commit
git checkout <hotfix-commit-sha>

# Secret scan
detect-secrets scan --all-files

# Dependency audit
npm audit --production

# Tests
npm test

# SAST
semgrep --config auto --severity ERROR .
```

**Step 2 — Verify:**
```bash
# Verify the hotfix commit is now on all branches
git branch --contains <hotfix-commit-sha>
# Should include: main, develop, and any active release branches

# Verify no secrets were introduced
git diff <pre-hotfix-sha>..<hotfix-commit-sha> | grep -iE "password|secret|token|api_key" | grep -v "test\|mock\|example"
```

**Step 3 — Prevent:**
```yaml
# Enforce branch protection — no bypass for anyone
# GitHub repo settings → Branches → Branch protection rules:
# ✅ Require status checks to pass before merging
# ✅ Require branches to be up to date
# ✅ Do not allow bypassing the above settings (even for admins)
```

- Remove `--no-verify` from any team scripts or aliases
- Add `[skip ci]` detection to branch protection (block commits with skip markers)

**Step 4 — Harden:**
1. Create a fast-path CI pipeline for hotfixes (runs essential checks in <5 min)
2. Require post-deploy retroactive CI run for any emergency bypass
3. Add incident post-mortem requirement for every CI bypass

---

### Playbook: Stale Feature Flag Gating Security

**Step 1 — Immediate Fix:**
1. Identify the flag gating security behavior
2. Make the security code unconditional (remove the flag wrapper)
3. Clean up the flag from the flag service

```typescript
// Before: auth gated behind feature flag (DANGEROUS)
if (featureFlags.isEnabled('new-auth-check')) {
  requireAuth(req);
}
processRequest(req);

// After: auth is unconditional
requireAuth(req);
processRequest(req);
```

**Step 2 — Verify:**
```bash
# Search for any remaining references to the removed flag
grep -rn "new-auth-check" --include="*.ts" --include="*.js" --include="*.py" .
# Should return 0 results

# Verify auth works without the flag
curl -X GET http://localhost:3000/protected-endpoint
# Should return 401 Unauthorized (no auth token)

curl -X GET http://localhost:3000/protected-endpoint -H "Authorization: Bearer valid-token"
# Should return 200 OK
```

**Step 3 — Prevent:**
- Add linting rule to detect feature flags wrapping auth/security code
- Implement quarterly flag audit — all flags >90 days old must be reviewed
- Tag security-relevant flags in flag service with `security:true` metadata

```bash
# CI check: find feature flags gating auth code
grep -B2 -A2 "featureFlags\.\(isEnabled\|evaluate\|getFlag\)" --include="*.ts" --include="*.js" . | \
  grep -A4 "auth\|security\|permission\|requireAuth\|isAuthenticated" && \
  echo "WARNING: Feature flag found near security code — review required"
```

**Step 4 — Harden:**
1. Establish policy: security checks must never be behind feature flags
2. Use separate flag categories — "feature" vs "operational" vs "security" — with different lifecycle rules
3. Set up automated alerts for feature flags older than 90 days

---

### Playbook: Missing Rollback Path for Migration

**Step 1 — Immediate Fix:**
1. Write the DOWN/rollback migration for the existing UP migration
2. Test the rollback in a staging environment
3. Deploy the rollback migration file

```sql
-- Example: UP migration added a column
-- UP: ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE;

-- Write the missing DOWN migration:
-- DOWN:
ALTER TABLE users DROP COLUMN IF EXISTS email_verified;
```

```python
# Django migration example
class Migration(migrations.Migration):
    dependencies = [('users', '0042_add_email_verified')]

    operations = [
        # Always define reverse operation
        migrations.RemoveField(
            model_name='user',
            name='email_verified',
        ),
    ]
```

**Step 2 — Verify:**
```bash
# Run migration forward and backward in staging
python manage.py migrate users 0042  # forward
python manage.py migrate users 0041  # rollback
python manage.py migrate users 0042  # forward again

# Verify data integrity after round-trip
python manage.py dbshell -c "SELECT count(*) FROM users;"
```

**Step 3 — Prevent:**
```bash
# CI check: ensure every migration has a rollback
#!/bin/bash
for migration in migrations/*.sql; do
  if grep -q "UP\|-- migrate:up" "$migration" && ! grep -q "DOWN\|-- migrate:down" "$migration"; then
    echo "FAIL: $migration has no DOWN migration"
    exit 1
  fi
done

# Django: check all migrations are reversible
python manage.py migrate --check --plan | grep -i "irreversible" && echo "FAIL: Irreversible migration found" && exit 1
```

**Step 4 — Harden:**
1. For destructive operations (DROP COLUMN, ALTER TYPE), use 3-phase expand-contract pattern
2. Test full migration chain from scratch in CI (migrate up from empty → migrate all down → migrate all up)
3. Require staging deployment with rollback test before production migration
4. Keep backup of pre-migration database state for manual recovery

---

## Git & GitHub Workflows

### Playbook: Force Push Overwrote Shared History

**Step 1 — Immediate Fix:**
1. Identify the lost commits using the reflog on any machine that had the original history
2. Recover the branch to its pre-force-push state
3. Notify all team members to update their local copies

```bash
# On a machine that still has the original commits:
git reflog show origin/main

# Find the last known good commit before the force push
# Example: origin/main@{1} is the pre-force-push state

# Restore the branch
git push origin origin/main@{1}:main --force-with-lease

# If no machine has the original: check GitHub's audit log
# The old HEAD SHA may still be recoverable via GitHub Support
```

**Step 2 — Verify:**
```bash
# Verify all expected commits are present
git log --oneline main | head -20

# Have all team members pull the restored branch
git fetch origin
git reset --hard origin/main  # or rebase their work
```

**Step 3 — Prevent:**
```bash
# Enable branch protection to block force pushes
gh api repos/{owner}/{repo}/branches/main/protection -X PUT \
  -f "allow_force_pushes=false"

# Set global alias to use --force-with-lease instead of --force
git config --global alias.pushf "push --force-with-lease"
```

**Step 4 — Harden:**
1. Enable `Do not allow bypassing the above settings` for admins
2. Add pre-push hook to warn about force pushes
3. Monitor audit log for force push events

---

### Playbook: Unsigned Commits Merged to Main

**Step 1 — Immediate Fix:**
1. Identify which commits are unsigned
2. If the commits are recent and the branch is not shared, amend with signature
3. If already shared, document the gap and enforce signing going forward

```bash
# Find unsigned commits on main
git log --pretty=format:"%H %G? %an %s" main | grep -v "^[a-f0-9]* G"
# G = good signature, N = no signature, B = bad signature

# If the last commit is yours and unsigned, amend it:
git commit --amend --no-edit -S
git push --force-with-lease  # only if not yet pulled by others

# If already shared, don't rewrite — just enforce going forward
```

**Step 2 — Verify:**
```bash
# Verify signing is configured
git config --global commit.gpgsign  # should be "true"
git config --global user.signingkey  # should be set

# Test signing works
echo "test" | git commit --allow-empty -S -m "test signed commit"
git log --show-signature -1
```

**Step 3 — Prevent:**
```bash
# Enforce signed commits via branch protection
gh api repos/{owner}/{repo}/branches/main/protection -X PUT \
  -f "required_signatures=true"

# Configure signing globally for all team members
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

**Step 4 — Harden:**
1. Add signed commit check to CI (verify all commits in PR are signed)
2. Document signing setup in team onboarding guide
3. Use SSH signing (simpler than GPG for most teams)

---

### Playbook: Deploy Key with Write Access on Public Repo

**Step 1 — Immediate Fix:**
1. Delete the current deploy key from the repository
2. Audit access logs for any unauthorized pushes using the key
3. Recreate as read-only deploy key

```bash
# List current deploy keys
gh api repos/{owner}/{repo}/keys --jq '.[] | "\(.id) \(.title) readonly=\(.read_only)"'

# Delete the write-access key
gh api repos/{owner}/{repo}/keys/{key_id} -X DELETE

# Generate new read-only deploy key
ssh-keygen -t ed25519 -C "deploy-key-{repo}" -f deploy_key -N ""

# Add as read-only
gh api repos/{owner}/{repo}/keys -f "title=CI Deploy Key" \
  -f "key=$(cat deploy_key.pub)" -f "read_only=true"
```

**Step 2 — Verify:**
```bash
# Confirm key is read-only
gh api repos/{owner}/{repo}/keys --jq '.[] | "\(.title): read_only=\(.read_only)"'

# Test that push is rejected
GIT_SSH_COMMAND="ssh -i deploy_key" git push origin main
# Should fail with "permission denied" or "read-only"
```

**Step 3 — Prevent:**
- Add deploy key audit to quarterly security review
- Document deploy key policy: read-only by default, write requires security team approval
- Use GitHub Apps instead of deploy keys when possible (better audit trail, fine-grained permissions)

**Step 4 — Harden:**
1. Rotate deploy keys every 90 days
2. Use unique deploy keys per repository (never share across repos)
3. Store deploy key private material in CI secret vault, not in repository

---

## Quick Reference: Fix by Category

| Category | Fastest Fix | Tool to Prevent |
|----------|------------|-----------------|
| SQL Injection | Parameterized queries | `bandit` (Python), `gosec` (Go), `eslint-plugin-security` (JS) |
| XSS | `textContent` instead of `innerHTML` | CSP header, `eslint-plugin-no-unsanitized` |
| Hardcoded Secrets | Move to env vars | `detect-secrets`, `git-secrets`, GitHub secret scanning |
| Missing Auth | Global auth middleware | Integration tests, route authorization tests |
| IDOR | Add ownership check | Authorization tests with multi-user scenarios |
| Missing Rate Limiting | `express-rate-limit` / `slowapi` | Load testing in CI |
| Unpinned Dependencies | Pin exact versions | `Renovate`, `Dependabot`, lock files |
| Container as Root | Add `USER` instruction | `trivy`, Kubernetes Pod Security Standards |
| Script Injection (CI) | Use `env:` instead of `${{ }}` in `run:` | `actionlint` |
| Overly Permissive IAM | Replace `*` with specific actions | `tfsec`, `checkov`, IAM Access Analyzer |
| CSV Injection | Prefix cells with `'` | Sanitization in export utility |
| Missing Security Headers | Use `helmet` (Express) or manual headers | Security header scanner in CI |
| Debug Build Shipped | Rebuild with release config | CI pre-upload validation script |
| Merge Conflict Dropped Auth | Restore lost check, review merged logic | CODEOWNERS, post-merge security tests |
| Hotfix Bypassed CI | Run CI retroactively, assess and fix | Branch protection (no bypass for admins) |
| Stale Feature Flag on Auth | Remove flag, make auth unconditional | Quarterly flag audit, linting rule |
| Missing Rollback Migration | Write DOWN migration, test round-trip | CI check for reversible migrations |
| Force Push to Shared Branch | Recover from reflog, restore branch | Branch protection (no force push) |
| Unsigned Commits | Amend with `-S` or enforce going forward | Branch protection (require signed commits) |
| Deploy Key Write Access | Recreate as read-only, audit access logs | Quarterly deploy key audit, use GitHub Apps |
