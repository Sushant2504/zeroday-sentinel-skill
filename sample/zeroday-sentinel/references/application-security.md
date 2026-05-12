# Application Security Reference

Language-specific SAST patterns for static analysis of application source code.

## Go

### Injection Vulnerabilities

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| SQL injection via fmt | `fmt.Sprintf` used to build SQL queries | CRITICAL | Use parameterized queries: `db.Query("SELECT * FROM t WHERE id = $1", id)` |
| SQL injection via concatenation | String concatenation in `db.Query()`, `db.Exec()` | CRITICAL | Use `$1`, `$2` placeholders with parameter arguments |
| Command injection | `exec.Command` with user-controlled input | CRITICAL | Validate input against allowlist. Pass args as separate `exec.Command("cmd", arg1, arg2)` elements |
| Template injection | `template.HTML()` wrapping unsanitized input | HIGH | Use `template.HTMLEscapeString()` or auto-escaping templates. Only mark trusted content as `template.HTML` |
| LDAP injection | String formatting in LDAP filter construction | HIGH | Use LDAP-specific escaping: `ldap.EscapeFilter(userInput)` |

**Grep patterns:**
```
fmt\.Sprintf.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)
exec\.Command\(
template\.HTML\(
```

### Credential & Crypto Issues

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Hardcoded credentials | `password :=`, `secret :=`, `token :=` with string literals | CRITICAL | Move to environment variables: `os.Getenv("DB_PASSWORD")`. Use a secret manager in production |
| Weak crypto | `crypto/md5`, `crypto/sha1` for security purposes | HIGH | Use `crypto/sha256` or `crypto/sha512`. For passwords use `golang.org/x/crypto/bcrypt` or `golang.org/x/crypto/argon2` |
| Insecure random | `math/rand` instead of `crypto/rand` for security | HIGH | Use `crypto/rand.Read()` for tokens/keys. Use `crypto/rand.Int()` for random integers |
| TLS skip verify | `InsecureSkipVerify: true` | HIGH | Remove `InsecureSkipVerify`. Add CA certificates to system trust store or configure custom `RootCAs` pool |
| HTTP without TLS | `http.ListenAndServe` (not `ListenAndServeTLS`) in production | MEDIUM | Use `http.ListenAndServeTLS(addr, certFile, keyFile, handler)`. Terminate TLS at load balancer if internal |

### Error Handling

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Swallowed errors | `_ = someFunction()` ignoring error returns | MEDIUM | Handle the error: `if err != nil { return fmt.Errorf("context: %w", err) }`. Use `errcheck` linter |
| Stack traces exposed | `debug.Stack()` or `runtime.Stack()` in HTTP responses | MEDIUM | Log stack traces server-side. Return generic error message to client: `http.Error(w, "Internal error", 500)` |
| Verbose error messages | Internal paths or system details in error strings returned to users | LOW | Use error codes instead of detailed messages. Map errors to user-friendly messages at the HTTP boundary |

## Python

### Injection & Unsafe Operations

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Code execution | `eval(`, `exec(`, `compile(` with variable input | CRITICAL | Use `ast.literal_eval()` for safe evaluation of data structures. Restructure to avoid eval entirely |
| Unsafe deserialization | `pickle.loads(`, `pickle.load(`, `yaml.load(` without `Loader=SafeLoader` | CRITICAL | Use `yaml.safe_load()`. Replace pickle with `json`. If pickle required, sign data with `hmac` before deserializing |
| Command injection | `subprocess.call(shell=True)`, `os.system(`, `os.popen(` | CRITICAL | Use `subprocess.run(["cmd", arg], shell=False, check=True)`. Pass args as list, never string |
| SQL injection | f-strings or `.format()` in SQL queries | CRITICAL | Use parameterized queries: `cursor.execute("SELECT * FROM t WHERE id = %s", (id,))`. Use ORM |
| Template injection | `jinja2.Template(user_input)` or `render_template_string(user_input)` | HIGH | Never construct templates from user input. Use `render_template()` with static template files and pass user data as variables |
| SSRF | `requests.get(user_input)` without URL validation | HIGH | Validate URL against allowlist of domains. Block private IP ranges. Use `urllib.parse.urlparse()` to verify scheme and host |
| Path traversal | `open(user_input)` without path sanitization | HIGH | Use `os.path.realpath()` then verify it starts with allowed base: `resolved.startswith(BASE_DIR)` |

**Grep patterns:**
```
eval\(
exec\(
pickle\.load
yaml\.load\((?!.*Loader=SafeLoader)
subprocess.*shell\s*=\s*True
os\.system\(
```

### Credential Issues

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Hardcoded secrets | `password = "`, `API_KEY = "`, `SECRET = "` | CRITICAL | Use `os.environ["SECRET"]` or `python-dotenv` with `.env` file (gitignored). Use secret manager in production |
| Credentials in logs | `logging.*password`, `print.*token` | HIGH | Add log redaction middleware. Use structlog with a redaction processor. Never log raw request bodies |
| Debug mode in production | `DEBUG = True`, `app.debug = True` | MEDIUM | Use environment variable: `DEBUG = os.environ.get("DEBUG", "false").lower() == "true"`. Ensure production env sets `DEBUG=false` |
| Assert for validation | `assert` statements for security checks (stripped in optimized mode) | MEDIUM | Replace `assert` with `if not condition: raise ValueError("...")`. Asserts are removed with `python -O` |

## JavaScript / TypeScript

### DOM & Injection

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| XSS via innerHTML | `.innerHTML =`, `.outerHTML =` with variable content | HIGH | Use `.textContent =` for text. For HTML, sanitize with DOMPurify: `el.innerHTML = DOMPurify.sanitize(data)` |
| XSS via document.write | `document.write(` with variable content | HIGH | Use DOM APIs: `document.createElement()`, `.appendChild()`. Never use `document.write` |
| eval usage | `eval(`, `new Function(`, `setTimeout(string)` | CRITICAL | Use `JSON.parse()` for data. Restructure to avoid eval. Use `setTimeout(fn, ms)` with function reference |
| Prototype pollution | `Object.assign(target, userInput)`, deep merge of user objects | HIGH | Use `Object.create(null)` for targets. Use libraries with prototype pollution protection. Validate input shape with schema |
| SQL injection | Template literals in SQL: `` `SELECT ... ${var}` `` | CRITICAL | Use parameterized queries: `db.query('SELECT * FROM t WHERE id = $1', [id])` |
| Regex DoS | User input in `new RegExp()` without sanitization | MEDIUM | Use `escape-string-regexp` to sanitize user input before `new RegExp()`. Set timeouts on regex operations |

**Grep patterns:**
```
\.innerHTML\s*=
document\.write\(
eval\(
new Function\(
Object\.assign\(.*,\s*(?:req\.|user|input|params|body)
```

### Node.js Specific

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Path traversal | `path.join(base, userInput)` without sanitization | HIGH | Use `path.resolve(base, userInput)` then verify `resolvedPath.startsWith(base)` |
| Insecure require | `require(variable)` with user-controlled path | CRITICAL | Use a static allowlist: `const modules = { a: require('./a') }; modules[name]` |
| Env secrets exposed | `process.env` values logged or returned in responses | HIGH | Never return `process.env` in API responses. Redact in logs. Use allowlist of safe env vars |
| Missing CSRF | Express routes without CSRF middleware on state-changing endpoints | MEDIUM | Use `csurf` middleware or `SameSite=Strict` cookies. Add CSRF token to all forms |

## Shell / Bash

### Command Injection & Safety

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unquoted variables | `$VAR` instead of `"$VAR"` in commands | HIGH | Always double-quote variables: `"$VAR"`. Use `shellcheck` to catch this automatically |
| eval with variables | `eval "$user_input"` or `eval $var` | CRITICAL | Remove `eval`. Use arrays for dynamic commands: `cmd=("ls" "-la" "$dir"); "${cmd[@]}"` |
| Backtick with user input | `` `$user_cmd` `` | CRITICAL | Use `$()` syntax and validate input. Never execute user-controlled strings |
| World-readable permissions | `chmod 777`, `chmod o+rwx` | HIGH | Use minimum permissions: `chmod 750` for dirs, `chmod 640` for files. Use `chmod u+x` for executables |
| Curl piped to shell | `curl ... \| sh`, `curl ... \| bash` | CRITICAL | Download first, verify checksum, then execute: `curl -o script.sh URL && sha256sum -c checksums.txt && bash script.sh` |
| Unsafe temp files | Using `/tmp/predictable_name` instead of `mktemp` | MEDIUM | Use `mktemp`: `tmpfile=$(mktemp)` or `tmpdir=$(mktemp -d)`. Cleanup with `trap "rm -f $tmpfile" EXIT` |

**Grep patterns:**
```
eval\s+["']?\$
chmod\s+777
chmod\s+[0-7]*[67][0-7][0-7]
curl.*\|\s*(sh|bash)
```

### Script Safety

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing set -e | Scripts without `set -e` or `set -euo pipefail` | LOW | Add `set -euo pipefail` at the top of every script |
| Missing input validation | Scripts accepting arguments without validation | MEDIUM | Validate args: `[[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]] \|\| { echo "Invalid input"; exit 1; }` |
| Credentials as arguments | `--password`, `--token` passed via command line (visible in `ps`) | HIGH | Use environment variables or stdin: `echo "$PASSWORD" \| cmd --password-stdin`. Never pass secrets as CLI args |

## Cross-Language Patterns

These apply to all languages:

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| TODO/FIXME security | `TODO.*security`, `FIXME.*auth`, `HACK.*credential` | LOW | Resolve the TODO. Create a ticket to track if not fixable now. Don't leave security TODOs in production code |
| Disabled security checks | `nosec`, `nolint:gosec`, `# noqa: S`, `eslint-disable.*security` | MEDIUM | Remove the suppression and fix the underlying issue. If suppression is justified, add a comment explaining why |
| Commented-out auth | Commented authentication/authorization checks | HIGH | Restore auth checks. If intentionally removed, delete the comments to avoid confusion. Verify the removal was approved |
| Base64 "encryption" | Using base64 encode/decode as a security measure | HIGH | Base64 is encoding, not encryption. Use AES-256-GCM for encryption, bcrypt/Argon2id for password hashing |

## Static Analysis Tool Setup

Run these to catch issues automatically:

```bash
# Python
pip install bandit
bandit -r . -f json -o bandit-report.json

# Go
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec ./...

# JavaScript/TypeScript
npm install --save-dev eslint-plugin-security
# Add to .eslintrc: { "plugins": ["security"], "extends": ["plugin:security/recommended"] }

# Shell
# Install shellcheck: https://github.com/koalaman/shellcheck
shellcheck scripts/*.sh

# Multi-language: Semgrep
pip install semgrep
semgrep --config=p/security-audit .
```
