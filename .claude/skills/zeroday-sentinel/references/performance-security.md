# Performance & Scaling Security Reference

Security checks for rate limiting, caching, CDN, load balancers, connection pools, queues, and scaling configurations. Poor performance configurations often create denial-of-service vulnerabilities and data leakage risks.

## Rate Limiting & Throttling

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No rate limiting on public endpoints | API/web endpoints without any request throttling | HIGH | Add rate limiting middleware. Tiered: 100/min general, 10/min auth, 5/min password reset |
| Rate limit by IP only | Relying solely on IP for rate limiting (bypassable via proxies) | MEDIUM | Rate limit by authenticated user ID when possible, IP as fallback. Combine both for defense-in-depth |
| Missing rate limit headers | Not returning `X-RateLimit-*` headers | LOW | Return `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` so clients can self-throttle |
| No backoff on auth failures | Login endpoints without exponential backoff | HIGH | Implement exponential backoff: 1s, 2s, 4s, 8s... after consecutive failures. Lock after 10 attempts for 15 minutes |
| Missing CAPTCHA on public forms | Registration, contact, password reset without bot protection | MEDIUM | Add CAPTCHA (reCAPTCHA v3, hCaptcha, Turnstile) on high-abuse forms |

**Remediation — Distributed rate limiting (Redis-backed):**
```javascript
const { RateLimiterRedis } = require('rate-limiter-flexible');

const rateLimiter = new RateLimiterRedis({
  storeClient: redisClient,
  keyPrefix: 'rl',
  points: 100,       // requests
  duration: 60,       // per 60 seconds
  blockDuration: 60,  // block for 60s if exceeded
});

app.use(async (req, res, next) => {
  try {
    const key = req.user?.id || req.ip;
    await rateLimiter.consume(key);
    next();
  } catch (err) {
    res.status(429).json({ error: 'Too many requests' });
  }
});
```

## Caching Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Cache poisoning risk | Caching responses that vary by user-controlled headers not in cache key | HIGH | Include all varying headers in cache key. Use `Vary` header correctly |
| Sensitive data cached | Auth tokens, PII, or session data in shared caches | CRITICAL | Set `Cache-Control: no-store, private` for authenticated/sensitive responses |
| Missing cache-busting | Static assets without versioned URLs | LOW | Use content-hash filenames: `app.a1b2c3.js`. Set long `max-age` on versioned assets |
| Cache key injection | User input included in cache keys without sanitization | HIGH | Sanitize and normalize cache keys. Don't include raw user input in cache keys |
| Stale data after auth change | Cache not invalidated after permission changes | HIGH | Invalidate user-specific caches on auth events (logout, role change, password reset) |
| Redis without auth | Redis cache instance accessible without password | CRITICAL | Set `requirepass` in Redis config. Use TLS for Redis connections. Bind to localhost or private network |
| Memcached without SASL | Memcached accessible without authentication | HIGH | Enable SASL authentication. Bind to private network. Use firewall rules |

**Remediation — Cache-Control for sensitive responses:**
```javascript
// Authenticated API responses
app.use('/api/private', (req, res, next) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
    'Vary': 'Authorization, Cookie',
  });
  next();
});

// Public static assets
app.use('/static', express.static('public', {
  maxAge: '1y',
  immutable: true,
}));
```

## CDN Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| CDN origin bypass | Origin server accessible directly, bypassing CDN security rules | HIGH | Restrict origin to only accept requests from CDN IPs. Use origin authentication headers |
| Missing WAF rules | CDN without Web Application Firewall rules | MEDIUM | Enable WAF with OWASP Core Rule Set. Add custom rules for your application's attack patterns |
| Wildcard CORS on CDN | CDN serving user content with `Access-Control-Allow-Origin: *` | HIGH | Use specific origin allowlists. Serve user content from a separate domain |
| Cache-Control override | CDN overriding application Cache-Control headers | MEDIUM | Configure CDN to respect origin Cache-Control headers. Review CDN caching rules for sensitive endpoints |
| Missing origin cloaking | Origin server IP discoverable via DNS history or error pages | MEDIUM | Use CDN-provided origin protection. Remove origin IP from DNS history. Don't expose origin IP in error pages |

## Load Balancer Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| TLS termination without re-encryption | LB terminates TLS but sends plaintext to backend | MEDIUM | Re-encrypt traffic between LB and backends (TLS to origin). Or use mTLS |
| Missing health check auth | Health check endpoints exposing internal status | LOW | Return minimal health check responses. Don't expose version numbers or internal state |
| Session affinity without fallback | Sticky sessions without graceful failover | MEDIUM | Use stateless session stores (Redis) instead of sticky sessions. If sticky is needed, implement fallback |
| Trusting X-Forwarded-For | Application trusting `X-Forwarded-For` without LB stripping/overwriting | HIGH | Configure LB to set `X-Forwarded-For`. Application should only trust the first (rightmost from LB) IP |
| Missing request size limits | No max request body size at LB level | HIGH | Set max body size at LB: nginx `client_max_body_size 10m;`, ALB default 64KB |
| HTTP/2 rapid reset | Server vulnerable to HTTP/2 rapid reset DoS (CVE-2023-44487) | HIGH | Update web servers and LBs to patched versions. Configure `http2_max_concurrent_streams` |

**Remediation — Nginx load balancer hardening:**
```nginx
upstream backend {
    server backend1:8080;
    server backend2:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;

    # TLS
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # Request limits
    client_max_body_size 10m;
    client_body_timeout 10s;
    client_header_timeout 10s;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    # Headers
    proxy_set_header X-Forwarded-For $remote_addr;  # Override, don't append
    proxy_set_header X-Real-IP $remote_addr;

    location /api/ {
        proxy_pass https://backend;
        proxy_ssl_verify on;
    }
}
```

## Connection Pool Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unbounded connection pools | No max connections configured | HIGH | Set max pool size based on expected load. Typical: 10-50 for DB, 100-200 for HTTP |
| Missing connection timeouts | No idle or connection timeout | HIGH | Set idle timeout (30-60s), connection timeout (5-10s), and query timeout (30s) |
| Connection string in code | Database connection string hardcoded | CRITICAL | Use environment variables or secret managers for connection strings |
| Missing connection retry logic | No retry with backoff on connection failure | MEDIUM | Implement retry with exponential backoff: 1s, 2s, 4s, max 5 retries |
| Connection leak detection | No monitoring for connection leaks | MEDIUM | Enable connection leak detection in your pool library. Set leak detection threshold |

**Remediation — Database connection pool (Node.js):**
```javascript
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,                     // max connections
  idleTimeoutMillis: 30000,    // close idle connections after 30s
  connectionTimeoutMillis: 5000, // timeout connecting after 5s
  statement_timeout: 30000,    // kill queries after 30s
  ssl: { rejectUnauthorized: true },
});
```

## Queue & Message Broker Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing message validation | Queue consumers processing messages without validation | HIGH | Validate message schema before processing. Use dead-letter queues for invalid messages |
| No dead-letter queue | Failed messages retried indefinitely | MEDIUM | Configure DLQ with max retry count (3-5). Monitor DLQ depth for alerts |
| Missing message size limits | No limit on published message size | HIGH | Set max message size at broker level. Validate on publish. Use S3/blob storage for large payloads |
| Unencrypted message broker | Broker connections without TLS | HIGH | Enable TLS for all broker connections. Use SASL authentication |
| Missing consumer concurrency limits | Unlimited concurrent message processing | MEDIUM | Set concurrency limits based on system capacity. Prevents resource exhaustion from burst |
| Poison message handling | No handling for messages that always fail processing | HIGH | Implement circuit breaker pattern. Move poison messages to DLQ after N failures |

## Resource Exhaustion Prevention

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unbounded loops | Loops without maximum iteration limits | HIGH | Add maximum iteration counts to all loops. Break after limit with error logging |
| Missing timeouts on external calls | HTTP/gRPC calls without timeout | HIGH | Set timeouts on every external call: connect (5s), read (30s), total (60s) |
| Unrestricted regex | User input in regex without complexity limits (ReDoS) | MEDIUM | Use RE2 or regex libraries with backtracking limits. Validate regex complexity before compiling |
| Missing memory limits | Process without memory limits (OOM risk) | MEDIUM | Set memory limits in container spec or process manager. Implement graceful degradation |
| Unbounded file reads | Reading files without size checks | HIGH | Check file size before reading. Set maximum allowed file size. Stream large files |
| Fork bomb potential | Code that spawns processes without limits | CRITICAL | Limit child processes. Use process pools with fixed size. Set ulimits |
| Missing request timeouts | Server without request timeout | HIGH | Set server-level request timeout: `server.setTimeout(30000)` |
| Unbounded query results | Database queries without LIMIT | HIGH | Always use LIMIT/pagination. Set a maximum page size. Default to a reasonable limit |

**Remediation — Timeout patterns:**
```javascript
// HTTP client with timeout (axios)
const response = await axios.get(url, {
  timeout: 5000,
  signal: AbortSignal.timeout(10000),
});

// Database query with timeout (PostgreSQL)
await pool.query({ text: 'SELECT * FROM orders WHERE user_id = $1 LIMIT 100', values: [userId], timeout: 5000 });

// Generic timeout wrapper
function withTimeout(promise, ms) {
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Timeout')), ms)
  );
  return Promise.race([promise, timeout]);
}
```

## Auto-Scaling Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing max instance limit | Auto-scaling without maximum instance count | HIGH | Set max instances to prevent cost explosion from DDoS: `maxReplicas: 10` |
| Scale-to-zero with cold start auth bypass | Serverless functions with auth check that fails during cold start | HIGH | Ensure auth middleware initializes before handling requests. Pre-warm critical functions |
| Missing scale-down cooldown | Rapid scale-down causing dropped requests | MEDIUM | Set scale-down cooldown period (300s typical). Use graceful shutdown signals |
| Cost-based DoS | Attacker can trigger expensive auto-scaling | HIGH | Set billing alerts. Implement rate limiting before auto-scaling triggers. Use WAF to filter attacks |

## Data Processing & Excel/CSV Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| CSV injection | User data exported to CSV/Excel without sanitization | HIGH | Prefix cells starting with `=`, `+`, `-`, `@`, `\t`, `\r` with a single quote `'`. Or use proper CSV libraries that handle escaping |
| XML bomb in Excel (XLSX) | Processing uploaded XLSX without entity expansion limits | HIGH | Use libraries that disable XML external entities. Set entity expansion limits |
| Unbounded CSV parsing | Parsing CSV without row/column limits | MEDIUM | Set maximum row count (e.g., 1M rows) and column count. Stream large files instead of loading into memory |
| PII in exports | Exporting sensitive data (SSN, credit cards) to spreadsheets | HIGH | Mask or redact PII in exports. Log export events for audit. Require additional auth for sensitive exports |
| Formula injection in spreadsheets | User input that becomes Excel formulas when exported | HIGH | Sanitize all cell values. Escape formula-triggering characters |

**Remediation — CSV injection prevention:**
```python
import csv
import io

def sanitize_csv_value(value):
    """Prevent CSV injection by escaping formula-triggering characters."""
    if isinstance(value, str) and value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
        return f"'{value}"
    return value

def export_csv(data, fields):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in data:
        safe_row = {k: sanitize_csv_value(v) for k, v in row.items()}
        writer.writerow(safe_row)
    return output.getvalue()
```

## Logging & Monitoring Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Sensitive data in logs | Logging passwords, tokens, credit cards, PII | HIGH | Sanitize log output. Use structured logging with field-level redaction. Never log request bodies wholesale |
| Missing security event logging | No logging for auth failures, permission denials, input validation failures | MEDIUM | Log all security events: login attempts, auth failures, permission denials, rate limit hits, input validation failures |
| Missing correlation IDs | No request tracing across services | LOW | Add correlation/request IDs to all log entries and propagate across service calls |
| Log injection | User input in log messages without sanitization | MEDIUM | Use structured logging (JSON). Sanitize user input in log messages. Escape newlines |
| Missing alerting | No alerts on security anomalies | MEDIUM | Set up alerts for: spike in auth failures, unusual traffic patterns, error rate increases, new IP accessing admin |

**Remediation — Structured security logging:**
```python
import structlog

logger = structlog.get_logger()

def log_security_event(event_type, user_id=None, ip=None, **kwargs):
    # Redact sensitive fields
    safe_kwargs = {k: '***REDACTED***' if k in ('password', 'token', 'secret') else v
                   for k, v in kwargs.items()}
    logger.warning("security_event",
        event_type=event_type,
        user_id=user_id,
        ip=ip,
        **safe_kwargs)
```
