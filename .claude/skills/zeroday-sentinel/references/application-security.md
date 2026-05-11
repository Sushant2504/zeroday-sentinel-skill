# Application Security Reference

Language-specific SAST patterns for static analysis of application source code.

## Go

### Injection Vulnerabilities

| Check | Pattern | Severity |
|-------|---------|----------|
| SQL injection via fmt | `fmt.Sprintf` used to build SQL queries | CRITICAL |
| SQL injection via concatenation | String concatenation in `db.Query()`, `db.Exec()` | CRITICAL |
| Command injection | `exec.Command` with user-controlled input | CRITICAL |
| Template injection | `template.HTML()` wrapping unsanitized input | HIGH |
| LDAP injection | String formatting in LDAP filter construction | HIGH |

**Grep patterns:**
```
fmt\.Sprintf.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)
exec\.Command\(
template\.HTML\(
```

### Credential & Crypto Issues

| Check | Pattern | Severity |
|-------|---------|----------|
| Hardcoded credentials | `password :=`, `secret :=`, `token :=` with string literals | CRITICAL |
| Weak crypto | `crypto/md5`, `crypto/sha1` for security purposes | HIGH |
| Insecure random | `math/rand` instead of `crypto/rand` for security | HIGH |
| TLS skip verify | `InsecureSkipVerify: true` | HIGH |
| HTTP without TLS | `http.ListenAndServe` (not `ListenAndServeTLS`) in production | MEDIUM |

### Error Handling

| Check | Pattern | Severity |
|-------|---------|----------|
| Swallowed errors | `_ = someFunction()` ignoring error returns | MEDIUM |
| Stack traces exposed | `debug.Stack()` or `runtime.Stack()` in HTTP responses | MEDIUM |
| Verbose error messages | Internal paths or system details in error strings returned to users | LOW |

## Python

### Injection & Unsafe Operations

| Check | Pattern | Severity |
|-------|---------|----------|
| Code execution | `eval(`, `exec(`, `compile(` with variable input | CRITICAL |
| Unsafe deserialization | `pickle.loads(`, `pickle.load(`, `yaml.load(` without `Loader=SafeLoader` | CRITICAL |
| Command injection | `subprocess.call(shell=True)`, `os.system(`, `os.popen(` | CRITICAL |
| SQL injection | f-strings or `.format()` in SQL queries | CRITICAL |
| Template injection | `jinja2.Template(user_input)` or `render_template_string(user_input)` | HIGH |
| SSRF | `requests.get(user_input)` without URL validation | HIGH |
| Path traversal | `open(user_input)` without path sanitization | HIGH |

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

| Check | Pattern | Severity |
|-------|---------|----------|
| Hardcoded secrets | `password = "`, `API_KEY = "`, `SECRET = "` | CRITICAL |
| Credentials in logs | `logging.*password`, `print.*token` | HIGH |
| Debug mode in production | `DEBUG = True`, `app.debug = True` | MEDIUM |
| Assert for validation | `assert` statements for security checks (stripped in optimized mode) | MEDIUM |

## JavaScript / TypeScript

### DOM & Injection

| Check | Pattern | Severity |
|-------|---------|----------|
| XSS via innerHTML | `.innerHTML =`, `.outerHTML =` with variable content | HIGH |
| XSS via document.write | `document.write(` with variable content | HIGH |
| eval usage | `eval(`, `new Function(`, `setTimeout(string)` | CRITICAL |
| Prototype pollution | `Object.assign(target, userInput)`, deep merge of user objects | HIGH |
| SQL injection | Template literals in SQL: `` `SELECT ... ${var}` `` | CRITICAL |
| Regex DoS | User input in `new RegExp()` without sanitization | MEDIUM |

**Grep patterns:**
```
\.innerHTML\s*=
document\.write\(
eval\(
new Function\(
Object\.assign\(.*,\s*(?:req\.|user|input|params|body)
```

### Node.js Specific

| Check | Pattern | Severity |
|-------|---------|----------|
| Path traversal | `path.join(base, userInput)` without sanitization | HIGH |
| Insecure require | `require(variable)` with user-controlled path | CRITICAL |
| Env secrets exposed | `process.env` values logged or returned in responses | HIGH |
| Missing CSRF | Express routes without CSRF middleware on state-changing endpoints | MEDIUM |

## Shell / Bash

### Command Injection & Safety

| Check | Pattern | Severity |
|-------|---------|----------|
| Unquoted variables | `$VAR` instead of `"$VAR"` in commands | HIGH |
| eval with variables | `eval "$user_input"` or `eval $var` | CRITICAL |
| Backtick with user input | `` `$user_cmd` `` | CRITICAL |
| World-readable permissions | `chmod 777`, `chmod o+rwx` | HIGH |
| Curl piped to shell | `curl ... \| sh`, `curl ... \| bash` | CRITICAL |
| Unsafe temp files | Using `/tmp/predictable_name` instead of `mktemp` | MEDIUM |

**Grep patterns:**
```
eval\s+["']?\$
chmod\s+777
chmod\s+[0-7]*[67][0-7][0-7]
curl.*\|\s*(sh|bash)
```

### Script Safety

| Check | Pattern | Severity |
|-------|---------|----------|
| Missing set -e | Scripts without `set -e` or `set -euo pipefail` | LOW |
| Missing input validation | Scripts accepting arguments without validation | MEDIUM |
| Credentials as arguments | `--password`, `--token` passed via command line (visible in `ps`) | HIGH |

## Cross-Language Patterns

These apply to all languages:

| Check | Pattern | Severity |
|-------|---------|----------|
| TODO/FIXME security | `TODO.*security`, `FIXME.*auth`, `HACK.*credential` | LOW |
| Disabled security checks | `nosec`, `nolint:gosec`, `# noqa: S`, `eslint-disable.*security` | MEDIUM |
| Commented-out auth | Commented authentication/authorization checks | HIGH |
| Base64 "encryption" | Using base64 encode/decode as a security measure | HIGH |
