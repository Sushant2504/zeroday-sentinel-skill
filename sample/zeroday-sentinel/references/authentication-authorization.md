# Authentication & Authorization Security Reference

Security checks for auth flows, session management, OAuth/OIDC, JWT, API keys, RBAC, and multi-factor authentication.

## Password Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Plaintext password storage | Storing passwords without hashing | CRITICAL | Use Argon2id (preferred), bcrypt (cost >= 12), or scrypt. Never MD5/SHA1/SHA256 for passwords |
| Weak hashing algorithm | MD5, SHA1, SHA256 for passwords | CRITICAL | Migrate to Argon2id. Run migration on next login: verify old hash, re-hash with Argon2id, store new hash |
| Missing password complexity | No minimum length or complexity requirements | MEDIUM | Minimum 8 characters. Check against breached password lists (HaveIBeenPwned API). Don't enforce complex rules (uppercase+number) — length matters more |
| Password in logs | Logging password values | CRITICAL | Never log passwords. Redact password fields in all logging middleware |
| Password in URL | Password sent via GET query parameter | HIGH | Always send passwords in POST request body over HTTPS |
| Missing brute force protection | No account lockout or rate limiting on login | HIGH | Rate limit: 5 attempts/minute. Lock account after 10 failures for 15 minutes. Notify user via email |

**Remediation — Password hashing (Node.js):**
```javascript
const argon2 = require('argon2');

// Hash password
const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536,  // 64 MB
  timeCost: 3,
  parallelism: 4,
});

// Verify password
const valid = await argon2.verify(hash, password);
```

**Remediation — Password hashing (Python):**
```python
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

# Hash
hashed = ph.hash(password)

# Verify
try:
    ph.verify(hashed, password)
    if ph.check_needs_rehash(hashed):
        new_hash = ph.hash(password)  # upgrade hash parameters
except VerifyMismatchError:
    # invalid password
```

## Session Management

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Predictable session IDs | Sequential or low-entropy session identifiers | CRITICAL | Use cryptographically random session IDs (128+ bits). Use framework's built-in session management |
| Missing session expiration | Sessions that never expire | HIGH | Set absolute timeout (8-24 hours). Set idle timeout (15-60 minutes). Implement sliding windows |
| Session fixation | Session ID doesn't change after login | HIGH | Regenerate session ID after authentication: `req.session.regenerate()` |
| Missing session invalidation on logout | Session not destroyed on logout | HIGH | Destroy server-side session data on logout. Clear session cookie. Invalidate any refresh tokens |
| Missing session invalidation on password change | Old sessions remain valid after password change | HIGH | Invalidate all sessions except current on password change. Store session creation timestamp and compare |
| Concurrent session limits | No limit on concurrent sessions per user | MEDIUM | Limit to 3-5 concurrent sessions. Notify user of new logins. Allow revoking other sessions |

**Remediation — Session management (Express.js):**
```javascript
const session = require('express-session');
const RedisStore = require('connect-redis').default;

app.use(session({
  store: new RedisStore({ client: redisClient }),
  name: '__Host-sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,  // reset expiry on activity
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 3600000,  // 1 hour
  },
}));

// Regenerate session after login
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  if (user) {
    req.session.regenerate((err) => {
      req.session.userId = user.id;
      req.session.save(() => res.json({ success: true }));
    });
  }
});
```

## JWT Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| JWT with `none` algorithm | Accepting or not rejecting `alg: none` | CRITICAL | Explicitly specify allowed algorithms: `algorithms: ['RS256']`. Never allow `none` |
| Symmetric signing in distributed systems | Using HS256 with shared secret across services | HIGH | Use RS256 or ES256 with asymmetric keys. Each service only needs the public key to verify |
| Missing expiration | JWTs without `exp` claim | HIGH | Set short expiration: 15-60 minutes for access tokens. Use refresh tokens for longer sessions |
| Long-lived JWTs | Access tokens with > 1 hour expiration | MEDIUM | Access token: 15 minutes. Refresh token: 7-30 days. Implement token rotation |
| JWT in localStorage | Storing JWT in localStorage (XSS accessible) | HIGH | Store in `HttpOnly` cookies. Or use BFF pattern (backend holds token, issues session cookie) |
| Missing audience/issuer validation | Not validating `aud` and `iss` claims | HIGH | Always verify `aud` matches your service and `iss` matches your auth server |
| Secret key too short | HMAC key shorter than the hash output (< 256 bits for HS256) | HIGH | Use 256+ bit keys for HS256. Generate with `crypto.randomBytes(64).toString('hex')` |
| Missing JTI for revocation | No JWT ID claim, making revocation impossible | MEDIUM | Include `jti` claim. Maintain a revocation list (Redis SET with TTL matching token lifetime) |

**Remediation — JWT verification (Node.js):**
```javascript
const jwt = require('jsonwebtoken');

function verifyToken(token) {
  return jwt.verify(token, publicKey, {
    algorithms: ['RS256'],       // explicit algorithm
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
    clockTolerance: 30,          // 30s clock skew
    maxAge: '1h',                // reject tokens older than 1 hour
  });
}
```

## OAuth 2.0 / OIDC Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing state parameter | OAuth flow without `state` for CSRF protection | HIGH | Generate random `state`, store in session, verify on callback. Use PKCE for additional protection |
| Missing PKCE | Authorization code flow without PKCE | HIGH | Implement PKCE (Proof Key for Code Exchange) for all OAuth clients, especially public clients (SPAs, mobile) |
| Client secret in frontend | OAuth client secret exposed in client-side code | CRITICAL | Use PKCE with public client (no secret). Or use BFF pattern where backend handles OAuth |
| Open redirect in callback | Redirect URI not strictly validated | HIGH | Use exact redirect URI matching. Never use wildcards. Register all valid redirect URIs with the OAuth provider |
| Token in URL fragment | Access token returned in URL hash (implicit flow) | HIGH | Use Authorization Code flow with PKCE instead of Implicit flow |
| Missing token revocation on logout | OAuth tokens not revoked when user logs out | MEDIUM | Call the provider's revocation endpoint on logout. Invalidate refresh tokens |

**Remediation — OAuth with PKCE (Node.js):**
```javascript
const crypto = require('crypto');

// Generate PKCE challenge
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// Authorization request
app.get('/auth/login', (req, res) => {
  const { verifier, challenge } = generatePKCE();
  const state = crypto.randomBytes(32).toString('hex');
  req.session.oauthState = state;
  req.session.pkceVerifier = verifier;

  const authUrl = new URL('https://provider.com/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', process.env.OAUTH_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', 'https://app.example.com/callback');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  res.redirect(authUrl.toString());
});
```

## API Key Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| API key in URL | Key sent as query parameter | MEDIUM | Send API keys in `Authorization` header or custom header (`X-API-Key`). Query params are logged |
| API key without scoping | Key grants full access without scope restrictions | HIGH | Issue scoped keys with minimum required permissions. Support read-only and read-write tiers |
| Missing key rotation | No mechanism to rotate API keys | MEDIUM | Support multiple active keys per account. Allow creating new key before revoking old one |
| API key stored in plaintext | Keys stored unhashed in database | HIGH | Store only the hash of API keys. On verification: hash the provided key and compare |
| Missing key expiration | API keys that never expire | MEDIUM | Set default expiration (90-365 days). Notify before expiration. Require re-creation |

## Multi-Factor Authentication (MFA)

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| MFA bypass in API | API endpoints that skip MFA verification | HIGH | Enforce MFA on sensitive operations: password change, payment, admin actions |
| TOTP without rate limiting | Unlimited TOTP code attempts | HIGH | Rate limit TOTP verification: 3-5 attempts per 30-second window |
| Backup codes stored in plaintext | Recovery codes not hashed | HIGH | Hash backup codes like passwords. One-time use: mark as consumed after use |
| Missing MFA for admin accounts | Admin/privileged accounts without mandatory MFA | HIGH | Require MFA for all admin and privileged accounts. Enforce at the organizational level |
| SMS as sole MFA | Using only SMS for MFA (vulnerable to SIM swapping) | MEDIUM | Support TOTP apps (Google Authenticator, Authy) and WebAuthn/passkeys as primary. Keep SMS as fallback only |

## Role-Based Access Control (RBAC)

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Hardcoded role checks | `if (user.role === 'admin')` scattered throughout code | MEDIUM | Centralize authorization logic. Use a policy engine or middleware pattern |
| Missing role hierarchy | No inheritance between roles | LOW | Define role hierarchy: `viewer < editor < admin < superadmin`. Check permissions, not roles |
| Permission escalation | Users can modify their own role | CRITICAL | Enforce role changes through admin-only endpoints. Verify requester has higher privilege than target |
| Missing audit trail | No logging of permission changes | MEDIUM | Log all role/permission changes with: who, what, when, from where |
| Stale permissions | Removed users retaining access | HIGH | Implement access reviews. Revoke permissions immediately on user deactivation. Use short-lived tokens |

**Remediation — RBAC middleware pattern:**
```javascript
// Define permissions
const PERMISSIONS = {
  'orders:read':   ['viewer', 'editor', 'admin'],
  'orders:write':  ['editor', 'admin'],
  'orders:delete': ['admin'],
  'users:manage':  ['admin'],
};

// Middleware
function requirePermission(permission) {
  return (req, res, next) => {
    const allowedRoles = PERMISSIONS[permission];
    if (!allowedRoles || !allowedRoles.includes(req.user.role)) {
      logger.warn('permission_denied', { user: req.user.id, permission, role: req.user.role });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Usage
app.delete('/orders/:id', requirePermission('orders:delete'), deleteOrder);
```

## Account Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| User enumeration via login | Different responses for "user not found" vs "wrong password" | MEDIUM | Return identical responses: "Invalid email or password". Use constant-time comparison |
| User enumeration via registration | "Email already registered" reveals existing accounts | MEDIUM | Return "If this email is registered, you'll receive a confirmation" and send email to existing user |
| User enumeration via password reset | "No account with this email" reveals user presence | MEDIUM | Always return "If this email exists, we sent a reset link". Send email regardless |
| Missing account lockout | No protection after many failed login attempts | HIGH | Lock account after 10 failed attempts for 15-30 minutes. Notify account owner via email |
| Insecure password reset | Reset tokens that are predictable, long-lived, or reusable | HIGH | Use 128-bit random tokens. Expire after 1 hour. Single use. Invalidate on password change |
