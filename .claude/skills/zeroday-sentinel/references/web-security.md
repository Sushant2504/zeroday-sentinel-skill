# Web Application Security Reference

Comprehensive security checks for frontend web applications, SPAs, server-rendered apps, and web APIs served over HTTP.

## OWASP Top 10 Coverage

### A01: Broken Access Control

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing auth on routes | Route handlers without authentication middleware | CRITICAL | Add auth middleware to every protected route. Use a deny-by-default pattern where routes are protected unless explicitly marked public |
| Client-side auth only | Authorization checks only in frontend JS, not on server | CRITICAL | Always enforce authorization server-side. Client-side checks are UX only — never security |
| IDOR vulnerabilities | Direct object references using user-supplied IDs without ownership check | HIGH | Verify the authenticated user owns or has access to the requested resource before returning it |
| Missing function-level access control | Admin endpoints accessible without role verification | CRITICAL | Implement role-based access control (RBAC) middleware. Check roles/permissions on every privileged endpoint |
| Directory traversal in file serving | `path.join(base, userInput)` or `sendFile(userInput)` without sanitization | HIGH | Use `path.resolve()` then verify the resolved path starts with the allowed base directory |

**Grep patterns:**
```
app\.(get|post|put|delete|patch)\s*\(.*(?!auth|protect|guard|middleware)
sendFile\(.*req\.
path\.join\(.*req\.
```

### A02: Cryptographic Failures

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| HTTP without TLS | Links, redirects, or API calls using `http://` in production | HIGH | Enforce HTTPS everywhere. Add HSTS header. Redirect HTTP to HTTPS at the load balancer |
| Weak hashing | MD5 or SHA1 for passwords or security tokens | HIGH | Use bcrypt, scrypt, or Argon2id for passwords. Use SHA-256+ for integrity checks |
| Missing encryption at rest | Sensitive data stored in plaintext (localStorage, cookies, database) | HIGH | Encrypt sensitive data at rest using AES-256-GCM. Use secure cookie flags |
| Insecure random | `Math.random()` for tokens, IDs, or security purposes | HIGH | Use `crypto.randomUUID()`, `crypto.getRandomValues()`, or `crypto.randomBytes()` |
| Sensitive data in URLs | Tokens, passwords, or PII in query parameters | MEDIUM | Move sensitive data to POST bodies or HTTP headers. Query params are logged in server logs, browser history, and referrer headers |

### A03: Injection

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| XSS via innerHTML | `.innerHTML =`, `.outerHTML =`, `document.write()` | HIGH | Use `.textContent` for text. Use DOM APIs or framework sanitization for HTML. If HTML is required, use DOMPurify |
| XSS via dangerouslySetInnerHTML | React `dangerouslySetInnerHTML` with user data | HIGH | Sanitize with DOMPurify before passing to dangerouslySetInnerHTML, or restructure to avoid raw HTML |
| Template injection | Server-side template rendering with unsanitized user input | CRITICAL | Use auto-escaping template engines. Never pass user input as template source |
| CSS injection | User input in `style` attributes or CSS custom properties | MEDIUM | Validate and sanitize CSS values. Use allowlists for permitted CSS properties |
| Header injection | User input in HTTP response headers without sanitization | HIGH | Validate and sanitize all header values. Reject values containing newlines (\r\n) |

**Grep patterns:**
```
\.innerHTML\s*=
dangerouslySetInnerHTML
document\.write\(
v-html\s*=
\[innerHTML\]\s*=
{{{.*}}}
```

### A07: Cross-Site Request Forgery (CSRF)

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing CSRF tokens | State-changing forms/endpoints without CSRF protection | HIGH | Implement CSRF tokens (Synchronizer Token Pattern or Double Submit Cookie). Use `SameSite=Lax` or `Strict` cookies |
| CSRF on API endpoints | REST APIs relying solely on cookies for auth without CSRF | MEDIUM | Use token-based auth (Bearer tokens) for APIs, or add CSRF tokens. `SameSite=Strict` cookies also mitigate |
| GET requests with side effects | GET endpoints that modify data | HIGH | Ensure GET requests are idempotent and read-only. Move state-changing operations to POST/PUT/DELETE |

## Security Headers

| Header | Expected Value | Severity | Remediation |
|--------|---------------|----------|-------------|
| `Content-Security-Policy` | Restrictive policy (no `unsafe-inline`, no `unsafe-eval`) | HIGH | Start with `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.yourdomain.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` and loosen as needed |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | HIGH | Add HSTS header. Submit to HSTS preload list for maximum protection |
| `X-Content-Type-Options` | `nosniff` | MEDIUM | Add `X-Content-Type-Options: nosniff` to prevent MIME-type sniffing attacks |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | MEDIUM | Add `X-Frame-Options: DENY` unless framing is required. Also use CSP `frame-ancestors` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or `no-referrer` | LOW | Add `Referrer-Policy: strict-origin-when-cross-origin` to limit referrer data leakage |
| `Permissions-Policy` | Restrict unused browser features | LOW | Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` to disable unused features |
| `X-XSS-Protection` | `0` (disable legacy filter) | LOW | Set to `0` — modern browsers don't need it and the legacy filter can introduce vulnerabilities |

**How to add headers (by framework):**

```javascript
// Express.js — use helmet
const helmet = require('helmet');
app.use(helmet());

// Next.js — next.config.js
headers: [{ source: '/(.*)', headers: securityHeaders }]

// Nginx
add_header Content-Security-Policy "default-src 'self';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

## Cookie Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing `Secure` flag | Cookies set without `Secure` attribute | HIGH | Add `Secure` flag so cookies are only sent over HTTPS |
| Missing `HttpOnly` flag | Session/auth cookies without `HttpOnly` | HIGH | Add `HttpOnly` to prevent JavaScript access to auth cookies |
| Missing `SameSite` attribute | Cookies without `SameSite` | MEDIUM | Set `SameSite=Lax` (default in modern browsers) or `Strict` for session cookies |
| Overly broad `Domain` | Cookie domain set to parent domain unnecessarily | MEDIUM | Set cookie domain to the most specific subdomain needed |
| Missing `__Host-` prefix | Session cookies without `__Host-` prefix | LOW | Use `__Host-` prefix for session cookies: `__Host-session=abc; Secure; Path=/; HttpOnly; SameSite=Lax` |
| Long-lived session cookies | Session cookies with `Max-Age` > 24 hours | MEDIUM | Set reasonable session lifetimes. Use sliding windows with absolute maximum |

**Remediation example:**
```javascript
// Express.js session cookie
app.use(session({
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 3600000, // 1 hour
    path: '/',
  },
  name: '__Host-session',
}));
```

## CORS Configuration

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Wildcard origin | `Access-Control-Allow-Origin: *` with credentials | CRITICAL | Use a specific allowlist of origins. Never use `*` with `Access-Control-Allow-Credentials: true` |
| Reflected origin | Reflecting the `Origin` header without validation | HIGH | Validate the `Origin` header against an explicit allowlist of trusted domains |
| Overly broad methods | `Access-Control-Allow-Methods: *` | MEDIUM | List only the HTTP methods actually needed: `GET, POST, OPTIONS` |
| Sensitive headers exposed | `Access-Control-Expose-Headers` including auth headers | MEDIUM | Only expose headers the frontend genuinely needs |

**Remediation example:**
```javascript
// Express.js CORS
const cors = require('cors');
app.use(cors({
  origin: ['https://app.example.com', 'https://admin.example.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400,
}));
```

## Client-Side Storage Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Tokens in localStorage | JWTs or auth tokens in `localStorage` | HIGH | Store tokens in `HttpOnly` cookies or use the BFF (Backend for Frontend) pattern. localStorage is accessible via XSS |
| Sensitive data in sessionStorage | PII or secrets in `sessionStorage` | MEDIUM | Minimize sensitive data in client storage. Use server-side sessions |
| Unencrypted IndexedDB | Sensitive data in IndexedDB without encryption | MEDIUM | Encrypt sensitive data before storing in IndexedDB. Consider using the Web Crypto API |
| Cache-Control for sensitive pages | Missing `Cache-Control: no-store` on authenticated pages | MEDIUM | Add `Cache-Control: no-store, no-cache, must-revalidate` for pages with sensitive data |

## Subresource Integrity (SRI)

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| External scripts without SRI | `<script src="https://cdn...">` without `integrity` attribute | MEDIUM | Add `integrity="sha384-..."` and `crossorigin="anonymous"` to all external script and link tags |
| External stylesheets without SRI | `<link href="https://cdn..." rel="stylesheet">` without `integrity` | MEDIUM | Generate SRI hashes with `shasum -b -a 384 file.js \| xxd -r -p \| base64` |

## Frontend Framework-Specific Checks

### React

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| dangerouslySetInnerHTML | Usage with user-controlled data | HIGH | Use DOMPurify: `dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(data)}}` |
| href javascript: | `href="javascript:..."` or user-controlled `href` | HIGH | Validate URLs start with `https://` or `/`. Reject `javascript:` and `data:` schemes |
| Exposed env vars | `REACT_APP_*` or `NEXT_PUBLIC_*` with secrets | CRITICAL | Never put secrets in client-exposed env vars. Use server-side API routes |
| SSR injection | Unsanitized data in server-side rendered HTML | HIGH | Use framework auto-escaping. Sanitize before serializing to `<script>` tags |

### Vue

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| v-html directive | `v-html` with user-controlled data | HIGH | Use `v-text` or sanitize with DOMPurify before using `v-html` |
| Unvalidated :href | Dynamic `:href` with user input | HIGH | Validate URLs. Use a URL validation function that rejects dangerous schemes |

### Angular

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| bypassSecurityTrust* | `bypassSecurityTrustHtml()`, `bypassSecurityTrustUrl()` | HIGH | Avoid bypass functions. Use Angular's built-in sanitization. If bypass is needed, sanitize with DOMPurify first |
| Template injection | Server-side rendering of Angular templates with user data | CRITICAL | Never construct Angular templates from user input |
