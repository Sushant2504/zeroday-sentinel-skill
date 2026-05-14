# Verification Checklist Reference

Procedures for verifying every factual claim in the groundwork report. This is a mandatory quality gate — no claim should appear in the final report without verification.

## Verification Principles

1. Every claim must cite a specific file path and, where applicable, a line number
2. Claims that cannot be verified are marked `UNVERIFIED` and noted in the verification summary
3. Statistics must be reproducible by re-running the specified command
4. Architecture claims must be traceable through actual import/dependency chains
5. Verification is non-negotiable — it runs after all analysis agents complete and before report generation

## Claim Categories and Verification Procedures

### File Existence Claims

Claims that a file or directory exists in the project.

| Verification Method | Tool | Example |
|--------------------|------|---------|
| Check file exists | `find . -name "auth.py" -path "*/middleware/*"` | "Auth middleware at `src/middleware/auth.py`" |
| Check directory exists | `find . -type d -name "migrations"` | "Migrations directory at `src/db/migrations/`" |
| Check file pattern | `find . -name "*.test.ts" -path "*/auth/*"` | "Auth tests exist in `src/auth/`" |

**Pass criteria**: File/directory exists at the stated path.
**Fail action**: Remove the claim or correct the path.

### Code Pattern Claims

Claims about specific code constructs, patterns, or implementations.

| Verification Method | Tool | Example |
|--------------------|------|---------|
| Verify function exists | `grep -rn "func validateToken" src/` | "Token validation in `validateToken()`" |
| Verify class exists | `grep -rn "class UserService" src/` | "`UserService` handles user operations" |
| Verify import chain | `grep -n "import.*auth" src/api/routes.py` | "API routes import auth middleware" |
| Verify pattern usage | `grep -rn "try.*catch" --include="*.ts" src/` | "Error handling uses try/catch throughout" |

**Pass criteria**: The exact symbol, pattern, or construct exists as described.
**Fail action**: Correct the symbol name, update the description, or remove the claim.

### API Endpoint Claims

Claims about specific API routes, their methods, and handlers.

| Verification Method | Tool | Example |
|--------------------|------|---------|
| Verify route definition | `grep -rn "router\.\(get\|post\|put\|delete\)" src/routes/` | "`POST /api/users` creates a user" |
| Verify handler exists | `grep -rn "def create_user\|createUser" src/` | "`create_user` handler processes requests" |
| Verify auth decorator | `grep -B2 "def create_user" src/api/users.py` | "Endpoint requires authentication" |
| Count endpoints | `grep -rc "router\.\(get\|post\|put\|delete\)" src/routes/ \| awk -F: '{sum+=$2} END {print sum}'` | "47 API endpoints" |

**Pass criteria**: Route definition exists with the stated method and path.
**Fail action**: Correct the endpoint details or remove the claim.

### Dependency Claims

Claims about project dependencies, their versions, and usage.

| Verification Method | Tool | Example |
|--------------------|------|---------|
| Verify dependency listed | `grep "fastapi" requirements.txt` or `grep '"express"' package.json` | "Uses FastAPI 0.104.0" |
| Verify version | Check exact version string in manifest | "Pinned to express@4.18.2" |
| Verify usage in code | `grep -rn "from fastapi import" src/` | "FastAPI used for API layer" |
| Count dependencies | `grep -c "==" requirements.txt` | "23 Python dependencies" |

**Pass criteria**: Dependency exists in manifest with the stated version (if version claimed).
**Fail action**: Correct the version, update the description, or remove the claim.

### Statistics Claims

Claims about quantitative measurements (file counts, line counts, coverage percentages).

| Verification Method | Tool | Example |
|--------------------|------|---------|
| File count | `find . -name "*.py" -not -path "*/vendor/*" \| wc -l` | "145 Python source files" |
| Line count | `find . -name "*.py" -not -path "*/vendor/*" -exec cat {} + \| wc -l` | "12,000 lines of Python" |
| Test count | `find . -name "*_test.py" \| wc -l` | "47 test files" |
| Commit count | `git rev-list --count HEAD` | "1,234 commits" |
| Contributor count | `git shortlog -sn \| wc -l` | "8 contributors" |

**Pass criteria**: Re-running the command produces a number within 5% of the claimed value (small variance acceptable due to concurrent changes).
**Fail action**: Update the statistic to the verified value.

### Architecture Claims

Claims about system structure, component relationships, and data flow.

| Verification Method | Tool | Example |
|--------------------|------|---------|
| Component boundary | `find . -maxdepth 2 -type d \| sort` | "System has 4 top-level components" |
| Import direction | `grep -rn "from src.database" src/api/` | "API layer depends on database layer" |
| No reverse dependency | `grep -rn "from src.api" src/database/` (should return nothing) | "Database layer does not depend on API" |
| Entry point | `grep -rn "if __name__" *.py` or `grep -rn "func main" cmd/` | "Single entry point at `cmd/server/main.go`" |

**Pass criteria**: Import chains exist as described; boundaries hold as claimed.
**Fail action**: Correct the architecture description or note the deviation.

### Documentation Claims

Claims about documentation content, coverage, or quality.

| Verification Method | Tool | Example |
|--------------------|------|---------|
| Doc page exists | `find . -name "authentication.md" -path "*/docs/*"` | "Auth flow documented in `docs/authentication.md`" |
| Doc content matches | Read the file and verify the claimed content | "Documentation describes JWT token flow" |
| Last update date | `git log -1 --format="%ai" -- docs/auth.md` | "Last updated 2026-03-15" |
| Section exists | `grep -n "## Authentication" docs/arch.md` | "Architecture doc has authentication section" |

**Pass criteria**: Documentation exists and contains the described content.
**Fail action**: Correct the description or mark as stale/missing.

### Git Statistics Claims

Claims about repository history, contributor patterns, and code churn.

| Verification Method | Tool | Example |
|--------------------|------|---------|
| Commit velocity | `git rev-list --count --since="90 days ago" HEAD` | "127 commits in last 90 days" |
| Top contributor | `git shortlog -sn --no-merges HEAD \| head -1` | "alice is the top contributor with 340 commits" |
| Hotspot file | `git log --format= --name-only \| sort \| uniq -c \| sort -rn \| head -1` | "`src/api/routes.py` is the most-modified file" |
| Bus factor | Re-run the bus factor calculation from repo-stats.sh | "Bus factor of 2" |

**Pass criteria**: Command output matches the claimed statistic.
**Fail action**: Update to the verified value.

## Verification Report Format

```markdown
### Verification Summary

**Total Claims:** {N}
**Verified:** {N} ({percent}%)
**Auto-Corrected:** {N}
**Unverified:** {N}
**Failed:** {N}

| # | Claim | Category | Source File | Status | Notes |
|---|-------|----------|-----------|--------|-------|
| 1 | Uses PostgreSQL 15 | Dependency | docker-compose.yml:12 | PASS | `image: postgres:15` confirmed |
| 2 | 47 API endpoints | Statistic | — | CORRECTED | Actual count: 45 |
| 3 | Auth middleware at src/middleware/auth.py | File existence | src/middleware/auth.py | PASS | File exists |
| 4 | RabbitMQ integration | Architecture | — | FAIL | No evidence found, claim removed |
```

## Red Flags

Patterns that strongly indicate a claim is incorrect and needs immediate attention:

| Red Flag | What It Means | Action |
|----------|-------------|--------|
| Referenced file does not exist | Path is wrong or file was deleted | Search for the file by name; correct or remove |
| Claimed line number contains different code | Line numbers shifted or wrong file | Re-grep for the code pattern; update line reference |
| Statistics differ by more than 20% | Likely using wrong count method | Re-run with the correct parameters |
| Import chain is circular | Architecture claim may be misleading | Document the actual dependency pattern |
| Function/class name not found in codebase | Possible hallucination or rename | Search for similar names; correct or remove |
| Documentation references non-existent code | Doc is stale, not code claim wrong | Flag as stale documentation finding |

## Verification Workflow

1. **Collect all claims** from the four analysis agents' outputs
2. **Categorize each claim** using the categories above
3. **Run verification** for each claim using the specified method
4. **Classify results**: PASS, CORRECTED (auto-fix minor issues), UNVERIFIED (cannot confirm but not disproven), FAIL (disproven)
5. **Apply corrections**: Update corrected claims in the report, remove failed claims
6. **Generate verification summary** as the final section before the report is produced
