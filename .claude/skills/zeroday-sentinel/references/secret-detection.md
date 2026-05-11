# Secret Detection Reference

Patterns and procedures for identifying hardcoded secrets, API keys, tokens, and credentials.

## High-Confidence Secret Patterns

These patterns have low false-positive rates and should always be flagged.

### Cloud Provider Credentials

| Secret Type | Regex Pattern | Severity |
|-------------|---------------|----------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` | CRITICAL |
| AWS Secret Access Key | `(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}` | CRITICAL |
| AWS Session Token | `(?i)aws_session_token\s*[:=]\s*[A-Za-z0-9/+=]+` | CRITICAL |
| GCP Service Account Key | `"type"\s*:\s*"service_account"` (in JSON files) | CRITICAL |
| Azure Client Secret | `(?i)azure[_-]?client[_-]?secret\s*[:=]\s*["'][^"']+["']` | CRITICAL |
| Azure Storage Key | `(?i)AccountKey\s*=\s*[A-Za-z0-9/+=]{86,88}==` | CRITICAL |

### API Tokens & Keys

| Secret Type | Regex Pattern | Severity |
|-------------|---------------|----------|
| GitHub Token (classic) | `ghp_[A-Za-z0-9]{36,}` | CRITICAL |
| GitHub Token (fine-grained) | `github_pat_[A-Za-z0-9_]{82}` | CRITICAL |
| GitHub OAuth | `gho_[A-Za-z0-9]{36,}` | CRITICAL |
| GitLab Token | `glpat-[A-Za-z0-9_-]{20,}` | CRITICAL |
| Slack Bot Token | `xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}` | CRITICAL |
| Slack Webhook | `hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}` | HIGH |
| PagerDuty API Key | `(?i)pagerduty.*[:=]\s*["']?[A-Za-z0-9+/]{20}["']?` | HIGH |
| SendGrid API Key | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | CRITICAL |
| Stripe API Key | `[sr]k_(live\|test)_[A-Za-z0-9]{24,}` | CRITICAL |
| Twilio Auth Token | `(?i)twilio.*[:=]\s*["']?[a-f0-9]{32}["']?` | HIGH |

### Private Keys & Certificates

| Secret Type | Regex Pattern | Severity |
|-------------|---------------|----------|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | CRITICAL |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | CRITICAL |
| OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | CRITICAL |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | CRITICAL |
| PKCS8 Private Key | `-----BEGIN PRIVATE KEY-----` | CRITICAL |
| Certificate (not secret but verify) | `-----BEGIN CERTIFICATE-----` | LOW |

### Database & Connection Strings

| Secret Type | Regex Pattern | Severity |
|-------------|---------------|----------|
| PostgreSQL connection | `postgres://[^:]+:[^@]+@` | CRITICAL |
| MySQL connection | `mysql://[^:]+:[^@]+@` | CRITICAL |
| MongoDB connection | `mongodb(\+srv)?://[^:]+:[^@]+@` | CRITICAL |
| Redis with password | `redis://:[^@]+@` | CRITICAL |
| Generic connection string | `(?i)(password\|passwd\|pwd)\s*[:=]\s*["'][^"']{8,}["']` | HIGH |
| JDBC with password | `jdbc:[a-z]+://.*password=[^&\s]+` | CRITICAL |

### Generic Patterns (Higher False Positive Rate)

| Pattern | Context Needed | Severity |
|---------|---------------|----------|
| `(?i)(api[_-]?key\|apikey)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']` | Check if it's a real value, not a placeholder | HIGH |
| `(?i)(secret\|token)\s*[:=]\s*["'][A-Za-z0-9+/=]{20,}["']` | Verify not a test/mock value | HIGH |
| `(?i)bearer\s+[A-Za-z0-9._-]{20,}` | Could be in examples/docs | HIGH |
| `(?i)authorization.*[:=]\s*["']Basic\s+[A-Za-z0-9+/=]+["']` | Base64-encoded credentials | HIGH |

## Files to Prioritize

Scan these file patterns first — they are most likely to contain secrets:

| Priority | File Patterns |
|----------|--------------|
| Critical | `.env`, `.env.*`, `credentials.*`, `secrets.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx` |
| High | `config.*`, `settings.*`, `application.yml`, `application.properties`, `docker-compose*.yml` |
| Medium | `*.tf`, `*.tfvars`, `*.cfg`, `*.ini`, `*.conf`, `*.toml` |
| Low | Source code files, test files |

**Files that should NEVER be committed:**
```
.env
.env.local
.env.production
credentials.json
service-account-key.json
*.pem (private keys)
*.key
*.p12
*.pfx
.htpasswd
```

## False Positive Guidance

### Common False Positives

| Pattern | False Positive Indicator | Action |
|---------|------------------------|--------|
| `AKIA...` | In AWS SDK test fixtures, mock files | Check file path for `test`, `mock`, `fixture`, `example` |
| `-----BEGIN...-----` | Public certificates, test certs | Verify it's `PRIVATE KEY`, not `CERTIFICATE` or `PUBLIC KEY` |
| Generic `password = "..."` | Placeholder values | Check for `changeme`, `TODO`, `REPLACE`, `xxxxxxx`, `example` |
| Connection strings | Docker Compose local dev | Check if the file is clearly dev-only (e.g., `docker-compose.dev.yml`) |
| Base64 strings | Configuration data, non-secret encoded values | Verify context suggests it is a credential |

### Placeholder Values to Ignore

These are common placeholder patterns that should NOT be flagged:
```
changeme
CHANGE_ME
REPLACE_ME
your-*-here
xxx+
000+
example
placeholder
TODO
<.*>
\$\{.*\}
```

### Test/Mock Files to Deprioritize

If a secret pattern is found in these paths, reduce severity by one level:
- `**/test/**`, `**/tests/**`, `**/*_test.*`, `**/*_test_*`
- `**/mock/**`, `**/mocks/**`, `**/fixtures/**`
- `**/example/**`, `**/examples/**`, `**/sample/**`
- `**/testdata/**`, `**/fake*`

## Reporting Secrets

When reporting a found secret:

1. **Do NOT include the full secret value** in the report — truncate to first 4-8 characters
2. Include the file path and line number
3. Specify the secret type (from the tables above)
4. Recommend:
   - Immediately rotating the credential
   - Removing it from version history (`git filter-repo` or BFG)
   - Using environment variables or a secret manager instead
   - Adding the file pattern to `.gitignore`
