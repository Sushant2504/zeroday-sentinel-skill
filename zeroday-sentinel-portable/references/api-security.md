# API Security Reference

Security checks for REST APIs, GraphQL APIs, gRPC services, WebSocket endpoints, and API gateways.

## Authentication & Authorization

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unauthenticated endpoints | API routes without auth middleware | CRITICAL | Apply auth middleware globally and explicitly mark public routes. Use deny-by-default |
| Missing authorization | Authenticated endpoints without role/permission checks | HIGH | Add authorization middleware that verifies the user has the required role/permission for each endpoint |
| Broken object-level auth (BOLA/IDOR) | API returns resources by ID without ownership verification | CRITICAL | Always verify the authenticated user owns or has access to the requested resource |
| Broken function-level auth | Admin API endpoints accessible to regular users | CRITICAL | Implement separate middleware for admin routes. Verify role on every privileged endpoint |
| Mass assignment | Accepting and applying all request body fields to models | HIGH | Use explicit allowlists for accepted fields. Never pass raw request body to ORM update methods |

**Remediation — Deny-by-default auth (Express.js):**
```javascript
// Apply auth to all routes
app.use(authMiddleware);

// Explicitly opt out for public routes
app.get('/health', skipAuth, healthHandler);
app.post('/auth/login', skipAuth, loginHandler);
```

**Remediation — BOLA prevention:**
```python
# Before (vulnerable)
@app.get("/orders/{order_id}")
def get_order(order_id: int):
    return db.query(Order).get(order_id)

# After (fixed)
@app.get("/orders/{order_id}")
def get_order(order_id: int, user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id, Order.user_id == user.id).first()
    if not order:
        raise HTTPException(404)
    return order
```

## Input Validation

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing request validation | No schema validation on request bodies | HIGH | Use JSON Schema, Zod, Pydantic, or framework validators. Validate every field: type, length, format, range |
| Missing path parameter validation | Route params used directly without type/format check | MEDIUM | Validate path params are expected type (UUID, integer, etc.) and within allowed ranges |
| Missing query parameter validation | Query params used without sanitization | MEDIUM | Validate and sanitize all query parameters. Use strict typing and allowlists |
| Missing Content-Type validation | Accepting any Content-Type without verification | MEDIUM | Verify `Content-Type` header matches expected format. Reject unexpected content types |
| Unvalidated file uploads | File upload without type/size/name validation | HIGH | Validate MIME type (by magic bytes, not extension), enforce size limits, sanitize filenames, store outside webroot |
| Missing request size limits | No `max-body-size` or equivalent | HIGH | Set request body size limits: `app.use(express.json({ limit: '1mb' }))` |

**Remediation — Input validation (Zod + Express):**
```typescript
import { z } from 'zod';

const CreateUserSchema = z.object({
  email: z.string().email().max(254),
  name: z.string().min(1).max(100).regex(/^[a-zA-Z\s'-]+$/),
  age: z.number().int().min(13).max(150).optional(),
});

app.post('/users', (req, res) => {
  const result = CreateUserSchema.safeParse(req.body);
  if (!result.success) return res.status(400).json({ errors: result.error.issues });
  createUser(result.data);
});
```

**Remediation — Input validation (Pydantic + FastAPI):**
```python
from pydantic import BaseModel, EmailStr, constr, conint

class CreateUser(BaseModel):
    email: EmailStr
    name: constr(min_length=1, max_length=100, pattern=r"^[a-zA-Z\s'-]+$")
    age: conint(ge=13, le=150) | None = None

@app.post("/users")
def create_user(user: CreateUser):
    # Pydantic auto-validates; invalid input returns 422
    ...
```

## Rate Limiting

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No rate limiting | API endpoints without rate limiting | HIGH | Add rate limiting middleware. Use tiered limits: stricter on auth endpoints, lighter on read endpoints |
| Missing rate limit on login | `/login`, `/auth`, `/token` without rate limiting | CRITICAL | Apply strict rate limits: 5-10 attempts per minute per IP/account. Add exponential backoff after failures |
| Missing rate limit on registration | `/register`, `/signup` without rate limiting | HIGH | Limit registration to 3-5 per IP per hour. Add CAPTCHA for additional protection |
| Missing rate limit on password reset | `/forgot-password`, `/reset-password` without limits | HIGH | Limit to 3-5 per email per hour. Use constant-time responses (don't reveal if email exists) |
| Rate limit bypass via headers | Rate limiting by `X-Forwarded-For` which can be spoofed | MEDIUM | Use a trusted proxy configuration. Rate limit by authenticated user ID when possible, IP as fallback |

**Remediation — Rate limiting (Express.js):**
```javascript
const rateLimit = require('express-rate-limit');

// Global rate limit
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// Strict limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, try again later' },
});
app.use('/api/auth/', authLimiter);
```

**Remediation — Rate limiting (FastAPI):**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/auth/login")
@limiter.limit("5/minute")
def login(request: Request, credentials: LoginRequest):
    ...
```

## Response Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Verbose error messages | Stack traces, SQL errors, or internal paths in API responses | MEDIUM | Return generic error messages to clients. Log detailed errors server-side. Use error codes for debugging |
| Excessive data exposure | API returning full database objects including internal fields | HIGH | Use response serializers/DTOs. Only return fields the client needs. Never return `password`, `internal_id`, `created_by_ip` |
| Missing pagination | List endpoints returning unbounded results | HIGH | Always paginate list endpoints. Set maximum page size (e.g., 100). Default to a reasonable page size (e.g., 20) |
| Missing field filtering | No ability to limit returned fields | LOW | Support field selection (`?fields=id,name`) to reduce data exposure and improve performance |
| Sensitive data in response headers | Server version, framework info in response headers | LOW | Remove `X-Powered-By`, `Server` version headers. Configure framework to suppress them |

**Remediation — Response serialization:**
```python
# Before (vulnerable — exposes everything)
@app.get("/users/{id}")
def get_user(id: int):
    return db.query(User).get(id).__dict__

# After (fixed — explicit fields)
class UserResponse(BaseModel):
    id: int
    name: str
    email: str

@app.get("/users/{id}", response_model=UserResponse)
def get_user(id: int):
    return db.query(User).get(id)
```

## GraphQL-Specific Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Introspection enabled in production | `introspection: true` in production config | MEDIUM | Disable introspection in production: `introspection: process.env.NODE_ENV !== 'production'` |
| Missing query depth limiting | No maximum query depth configured | HIGH | Limit query depth to 5-10 levels: `depthLimit(10)` |
| Missing query complexity analysis | No cost analysis for complex queries | HIGH | Implement query complexity analysis. Reject queries exceeding a cost threshold |
| Batching attacks | No limit on batched queries | MEDIUM | Limit batch size (e.g., max 10 queries per request) |
| Missing field-level authorization | Resolver returns data without checking permissions | HIGH | Add authorization checks at the resolver level, not just the query level |

**Remediation — GraphQL hardening (Apollo Server):**
```javascript
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== 'production',
  plugins: [
    ApolloServerPluginLandingPageDisabled(),
  ],
  validationRules: [
    depthLimit(10),
    createComplexityLimitRule(1000),
  ],
});
```

## WebSocket Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing authentication on connect | WebSocket connections accepted without auth | HIGH | Authenticate during the WebSocket handshake (via token in query param or first message) |
| Missing origin validation | No `Origin` header check on WebSocket upgrade | HIGH | Validate the `Origin` header against allowed domains during upgrade |
| Missing message validation | WebSocket messages processed without validation | HIGH | Validate and sanitize all incoming WebSocket messages. Use schemas |
| Missing rate limiting | No limit on message frequency | MEDIUM | Rate limit WebSocket messages per connection (e.g., 10 messages/second) |
| Unbounded connection count | No limit on concurrent WebSocket connections | HIGH | Limit connections per IP/user. Set connection timeouts |

## API Versioning & Deprecation Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Old API versions still active | Deprecated API versions with known vulnerabilities still accessible | HIGH | Set sunset dates for old API versions. Return `Sunset` header. Redirect to current version |
| Missing API versioning | No versioning strategy (URL, header, or query param) | MEDIUM | Implement API versioning from the start. URL versioning (`/v1/`) is simplest |
| Undocumented endpoints | API endpoints not in OpenAPI/Swagger spec | MEDIUM | Document all endpoints. Use spec-first development. Run spec validation in CI |

## File Upload Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No file type validation | Accepting any file type | HIGH | Validate MIME type by reading magic bytes, not just file extension |
| No file size limit | Missing max file size | HIGH | Set size limits: `multer({ limits: { fileSize: 5 * 1024 * 1024 } })` (5MB) |
| Executable file upload | Accepting `.php`, `.jsp`, `.exe`, `.sh` | CRITICAL | Maintain an allowlist of accepted file types. Reject everything else |
| Files served from application domain | User uploads served from same origin as the app | HIGH | Serve user uploads from a separate domain/CDN to prevent XSS via uploaded files |
| Missing virus scanning | No malware scan on uploaded files | MEDIUM | Integrate ClamAV or a cloud antivirus API for uploaded file scanning |

**Remediation — Secure file upload (Express + Multer):**
```javascript
const multer = require('multer');
const fileType = require('file-type');

const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  storage: multer.memoryStorage(),
});

app.post('/upload', upload.single('file'), async (req, res) => {
  const type = await fileType.fromBuffer(req.file.buffer);
  const ALLOWED = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
  if (!type || !ALLOWED.includes(type.mime)) {
    return res.status(400).json({ error: 'Invalid file type' });
  }
  // Store to S3/separate domain, not local webroot
});
```
