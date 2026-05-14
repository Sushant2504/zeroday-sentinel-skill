# Critical Workflows Security Reference

Security checks for high-pressure developer workflows: app store deployments, merge conflicts, hotfixes, rollbacks, feature flags, and pre-release gates. These are the moments when security shortcuts are most tempting — and most dangerous.

## Release & Deployment Security

### App Store / Play Store Submission

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Debug build submitted | `android:debuggable="true"` or missing release signing config | CRITICAL | Verify `isDebuggable = false` in release `build.gradle`. Verify Xcode scheme uses Release configuration. Never submit debug builds |
| Test/staging API endpoints in production | Hardcoded staging URLs, `api-staging`, `dev.example.com` in release code | CRITICAL | Use build-time environment injection. Verify base URL resolves to production before submission |
| Test credentials in release | Demo accounts, test API keys, sandbox tokens shipped in production | HIGH | Strip test credentials from release builds. Use CI step to grep for test/sandbox patterns before upload |
| Missing privacy manifest (iOS) | No `PrivacyInfo.xcprivacy` when using required reason APIs | HIGH | Add privacy manifest declaring all required reason API usage. Required since Spring 2024 |
| Unsigned or ad-hoc signing | Missing distribution certificate, expired provisioning profile | CRITICAL | Use App Store distribution profile. Enroll in Play App Signing. Never distribute with ad-hoc/dev signing |
| Missing ProGuard/R8 (Android) | `minifyEnabled = false` in release build type | HIGH | Enable `isMinifyEnabled = true` and `isShrinkResources = true` for release builds |
| Source maps included in release | JavaScript bundle source maps (React Native) or Dart debug info (Flutter) shipped | MEDIUM | Use `--no-source-maps` for RN. Use `--obfuscate --split-debug-info` for Flutter. Upload maps to crash reporting service only |
| Leftover debug logging | `console.log`, `print()`, `Log.d()` with sensitive data in release | MEDIUM | Strip debug logs in release builds. Use ProGuard/R8 rules to remove `Log.d`/`Log.v`. Use build flavors |
| Missing app attestation | No Play Integrity API / App Attest integration | MEDIUM | Implement Play Integrity API (Android) and App Attest (iOS) to detect tampered environments |

**Remediation — Release build verification script:**
```bash
#!/bin/bash
set -euo pipefail

echo "=== Pre-submission Security Check ==="

# Android checks
if [ -f "app/build.gradle" ] || [ -f "app/build.gradle.kts" ]; then
  grep -r "isDebuggable\s*=\s*true" app/build.gradle* && echo "FAIL: debuggable=true in release" && exit 1
  grep -r "isMinifyEnabled\s*=\s*false" app/build.gradle* | grep -i release && echo "WARN: minify disabled for release"
fi

# iOS checks
if [ -d "*.xcodeproj" ] || [ -d "*.xcworkspace" ]; then
  grep -r "DEBUG" *.xcconfig 2>/dev/null | grep -v "//\|#" && echo "WARN: DEBUG references in xcconfig"
fi

# Universal checks
grep -rn "api-staging\|dev\.example\|localhost\|127\.0\.0\.1" --include="*.swift" --include="*.kt" --include="*.ts" --include="*.dart" src/ lib/ app/ 2>/dev/null && echo "FAIL: staging/dev URLs found" && exit 1
grep -rn "test_api_key\|sandbox_\|demo_password\|changeme" --include="*.swift" --include="*.kt" --include="*.ts" --include="*.dart" src/ lib/ app/ 2>/dev/null && echo "FAIL: test credentials found" && exit 1

echo "=== All pre-submission checks passed ==="
```

### Google Play App Signing

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Upload key stored in repo | `*.keystore` or `*.jks` committed to version control | CRITICAL | Remove keystore from repo. Add `*.keystore` and `*.jks` to `.gitignore`. Use CI secret storage |
| Signing config in build.gradle | `storePassword` / `keyPassword` hardcoded in build files | CRITICAL | Use environment variables: `storePassword System.getenv("KEYSTORE_PASSWORD")`. Store in CI secrets |
| Not enrolled in Play App Signing | App uses self-managed signing key | HIGH | Enroll in Google Play App Signing. Upload key is separate from app signing key — if upload key is compromised, Google can reset it |

**Remediation — Secure signing config (build.gradle.kts):**
```kotlin
android {
    signingConfigs {
        create("release") {
            storeFile = file(System.getenv("KEYSTORE_PATH") ?: "release.keystore")
            storePassword = System.getenv("KEYSTORE_PASSWORD")
            keyAlias = System.getenv("KEY_ALIAS")
            keyPassword = System.getenv("KEY_PASSWORD")
        }
    }
    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
        }
    }
}
```

### iOS Distribution Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Expired provisioning profile | Profile expiration date passed | CRITICAL | Regenerate in Apple Developer portal. Use `fastlane match` for team-wide profile management |
| Development cert used for distribution | Code signing identity is "iPhone Developer" not "iPhone Distribution" | CRITICAL | Use "Apple Distribution" certificate. Configure in Xcode target signing settings |
| Missing entitlements review | New entitlements added without security review | HIGH | Review all entitlements in `.entitlements` file before submission. Remove unused capabilities |
| Hardcoded team ID | Apple Team ID in committed xcconfig or Info.plist | MEDIUM | Use `DEVELOPMENT_TEAM` build setting from environment. Don't commit team-specific values |

**Remediation — Fastlane match for certificate management:**
```ruby
# Matchfile
git_url("https://github.com/org/certificates")
storage_mode("git")
type("appstore")
app_identifier(["com.example.app"])
username("ci@example.com")
```

### Staged Rollouts

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| 100% rollout without monitoring | Deploying to all users without staged percentage | HIGH | Start at 1-5% → 25% → 50% → 100%. Monitor crash rates, ANRs, error logs at each stage |
| No rollback trigger defined | Staged rollout without automatic halt conditions | HIGH | Define rollback triggers: crash rate > 2x baseline, error rate > 5%, latency p99 > 2x. Automate halt |
| Missing rollout monitoring | No dashboard or alerts for rollout health | MEDIUM | Set up monitoring for: crash-free rate, API error rate, user-reported issues, performance metrics |

## Merge Conflict Resolution Security

### Security-Critical Conflict Zones

When merge conflicts occur in these files, apply **extra scrutiny** — incorrect resolution can silently remove security controls:

| File/Area | Risk | What to Watch |
|-----------|------|--------------|
| Auth middleware / route guards | CRITICAL | Ensure auth checks aren't dropped, duplicated, or reordered |
| Input validation / sanitization | HIGH | Verify validation rules aren't lost — "accept theirs" often drops new validation |
| `.gitignore` | HIGH | Ensure secret file patterns aren't removed during resolution |
| Lock files (`package-lock.json`, `yarn.lock`, `go.sum`) | HIGH | Never manually edit — delete and regenerate, then review the diff |
| Security headers (CSP, CORS) | HIGH | Merged CSP policies may be overly permissive. Review combined directives |
| Firewall rules / security groups | HIGH | Merged rules may create unintended openings — review all rules post-merge |
| Permission/RBAC definitions | HIGH | Merging role definitions can grant unintended permissions |
| Migration files | MEDIUM | Conflicting migrations may apply in wrong order — test migration sequence |

### Common Merge Conflict Security Mistakes

| Mistake | Severity | Remediation |
|---------|----------|-------------|
| Accepting "both" changes on auth middleware | CRITICAL | Review merged auth logic end-to-end. Run auth test suite. Verify no duplicate or conflicting checks |
| Accepting "theirs" and losing input validation | HIGH | Diff the resolved file against both branches. Ensure all validation present in either branch survives |
| Deleting and regenerating lock file without review | HIGH | After regeneration: `git diff package-lock.json` to verify no unexpected package changes or version bumps |
| Merging CORS/CSP configs by combining | HIGH | Don't union CORS origins or CSP directives. Review the merged policy — combined may be more permissive than intended |
| Resolving `.gitignore` conflict by keeping shorter version | HIGH | Ensure all secret patterns (`*.pem`, `*.key`, `.env*`, `credentials.*`) are present in resolved file |
| Skipping tests after conflict resolution | HIGH | Always run full test suite after merge conflict resolution. Never assume "obvious" resolutions are correct |

**Remediation — Post-merge conflict verification:**
```bash
#!/bin/bash
set -euo pipefail

echo "=== Post-Merge Conflict Security Check ==="

# Check that auth middleware is intact
git diff HEAD~1 --name-only | grep -i "auth\|middleware\|guard\|permission" && {
  echo "WARNING: Auth-related files changed in merge. Manual review required."
  git diff HEAD~1 -- $(git diff HEAD~1 --name-only | grep -i "auth\|middleware\|guard\|permission")
}

# Check .gitignore still has secret patterns
for pattern in "*.pem" "*.key" ".env" "credentials" "secrets"; do
  grep -q "$pattern" .gitignore || echo "FAIL: .gitignore missing pattern: $pattern"
done

# Check lock file integrity
if git diff HEAD~1 --name-only | grep -q "package-lock.json\|yarn.lock"; then
  echo "Lock file changed — verifying integrity..."
  npm ci --ignore-scripts 2>/dev/null || echo "FAIL: Lock file may be corrupted"
fi

# Run security-relevant tests
echo "Running auth and security tests..."
npm test -- --grep "auth\|security\|permission\|validation" 2>/dev/null || true

echo "=== Post-merge check complete ==="
```

## Hotfix & Emergency Deployment

### Emergency Change Security Checklist

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| CI checks bypassed | `--no-verify`, `[skip ci]`, `[ci skip]` in commit message | CRITICAL | Never skip CI for production hotfixes. If CI is slow, fix the pipeline — don't bypass it |
| Code review skipped | Direct push to main/production without PR | HIGH | Require at least 1 reviewer even for hotfixes. Use CODEOWNERS for security-critical paths. Set branch protection |
| Pre-commit hooks bypassed | `git commit --no-verify` | HIGH | Don't bypass hooks. If a hook is blocking the fix, the hook may be catching a real issue |
| Security scan skipped | Manual override of required security scanning | HIGH | Run security scan even for hotfixes. Use `--quick` mode if available for faster feedback |
| Temporary hardcoded credentials | Quick-fix with inline credentials "to be changed later" | CRITICAL | Never hardcode credentials, even temporarily. Use existing secret manager. The "temporary" fix often becomes permanent |
| Missing post-deployment verification | Hotfix deployed without smoke test | HIGH | Run smoke tests immediately after deployment. Verify the fix works AND nothing else broke |

### Hotfix Branch Hygiene

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Hotfix not merged back | Fix applied to production but not merged to main/develop | HIGH | Always merge hotfix back to all active branches. Automate with branch protection rules |
| Cherry-pick without context | Cherry-picking fix without related test or config changes | MEDIUM | Cherry-pick the full fix including tests, config changes, and migration files |
| Hotfix branch left open | Stale hotfix branches with elevated permissions | MEDIUM | Delete hotfix branches after merge. Set auto-delete in GitHub repo settings |
| Drift between hotfix and main | Multiple hotfixes without integration | HIGH | Regularly merge main into release branches. Don't let hotfixes accumulate without integration |

**Remediation — Hotfix workflow with security gates:**
```yaml
# .github/workflows/hotfix.yml
name: Hotfix Pipeline
on:
  push:
    branches: ['hotfix/**']

permissions: read-all

jobs:
  security-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4
      - name: Secret scan
        run: |
          pip install detect-secrets
          detect-secrets scan --baseline .secrets.baseline
      - name: Dependency audit
        run: npm audit --production || true
      - name: Run tests
        run: npm test

  deploy:
    needs: security-gate
    runs-on: ubuntu-latest
    environment: production  # requires manual approval
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4
      - name: Deploy hotfix
        run: ./scripts/deploy.sh
      - name: Smoke test
        run: ./scripts/smoke-test.sh
      - name: Notify merge-back required
        run: echo "::warning::Hotfix deployed. Merge back to main required."
```

### Temporary Security Exceptions

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Permanent `// FIXME: security` comments | TODO/FIXME about security issues older than 7 days | HIGH | Track in issue tracker with deadline. Set up CI to fail on stale security TODOs |
| Disabled security check without expiry | `@SuppressWarnings("security")` or `# nosec` without tracking | HIGH | Add expiry date: `# nosec:expires=2026-06-01:reason=hotfix-123`. Create follow-up ticket |
| Temporary firewall/CORS relaxation | Overly broad rules added for emergency with no removal plan | HIGH | Set calendar reminder. Add expiry comment. Create revert PR in advance, schedule merge |

**Remediation — Auto-expiring security exception (CI check):**
```bash
#!/bin/bash
# Check for expired security exceptions
TODAY=$(date +%Y-%m-%d)
grep -rn "nosec:expires=" --include="*.py" --include="*.go" --include="*.js" --include="*.ts" . | while read -r line; do
  EXPIRY=$(echo "$line" | grep -oP 'expires=\K[0-9-]+')
  if [[ "$EXPIRY" < "$TODAY" ]]; then
    echo "EXPIRED SECURITY EXCEPTION: $line"
    EXIT_CODE=1
  fi
done
exit ${EXIT_CODE:-0}
```

## Rollback Security

### Database Rollback Risks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Destructive migration without rollback | `DROP TABLE`, `DROP COLUMN`, `ALTER TYPE` with no down migration | CRITICAL | Always write a reversible migration. For destructive ops: add new column → migrate data → drop old column in separate migration |
| Data loss on rollback | Migration that deletes data is not reversible | HIGH | Before destructive migrations: create backup table, verify restore procedure, test rollback in staging |
| Migration order conflict | Multiple migrations targeting same table merged from different branches | HIGH | Re-sequence migrations after merge. Test full migration chain from scratch in staging |
| Seed data in migration | Test/seed data mixed into schema migrations | MEDIUM | Separate seed data from schema migrations. Never include test data in production migration files |

**Remediation — Reversible migration pattern (SQL):**
```sql
-- UP migration
ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE;

-- DOWN migration (always write this)
ALTER TABLE users DROP COLUMN IF EXISTS email_verified;
```

**Remediation — Safe destructive migration (3-phase):**
```sql
-- Phase 1: Add new column (reversible)
ALTER TABLE users ADD COLUMN new_status VARCHAR(50);
UPDATE users SET new_status = CASE status WHEN 0 THEN 'inactive' WHEN 1 THEN 'active' END;

-- Phase 2: App code reads from new_status (deploy, verify)

-- Phase 3: Drop old column (separate migration, after Phase 2 is stable)
ALTER TABLE users DROP COLUMN status;
ALTER TABLE users RENAME COLUMN new_status TO status;
```

### Blue-Green / Canary Deployment Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Session incompatibility between versions | Old sessions invalid in new version or vice versa | HIGH | Use backward-compatible session format. Version your session schema. Support N-1 session format during rollout |
| API contract break between versions | Breaking changes served to clients hitting different versions | HIGH | Use API versioning. Old and new versions must coexist during rollout. Never break contracts in-place |
| Mixed-version database access | Old and new code accessing same tables with different schemas | HIGH | Use expand-contract pattern: add new columns, deploy new code, then remove old columns |
| CDN serving stale assets | Old cached assets served with new API responses | MEDIUM | Version static assets with content hashes. Invalidate CDN cache at deployment. Use immutable cache headers |
| Cookie/token incompatibility | Auth tokens from old version rejected by new version | CRITICAL | Maintain backward-compatible token validation during rollout. Support both signing keys temporarily |

### Rollback Verification Checklist

| Check | What to Verify |
|-------|---------------|
| Authentication | Users can still log in. Sessions are valid. OAuth flows complete |
| Authorization | Permission checks work. RBAC roles resolve correctly |
| Secrets | All secrets/configs still valid. No references to removed env vars |
| API contracts | All client-facing endpoints respond correctly. No 404s on expected routes |
| Database state | Schema matches code expectations. No orphaned references |
| Feature flags | Flags point to correct variations. No stale flag references |
| External integrations | Webhooks, callbacks, OAuth redirect URIs still valid |

## Feature Flag Security

### Security-Critical Flag Patterns

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Auth check behind feature flag | Authentication/authorization gated by flag | CRITICAL | Never gate security controls behind feature flags. Security checks must be unconditional |
| Client-side flag evaluation for security decisions | Security logic based on flag value received from client | HIGH | Evaluate security-relevant flags server-side only. Client can manipulate flag values |
| Stale flag with security implications | Feature flag older than 90 days that gates security behavior | HIGH | Audit and clean up stale flags quarterly. Remove flag and make code unconditional |
| Flag default is insecure | Flag defaults to permissive/insecure when evaluation fails | HIGH | Default to secure/restrictive when flag evaluation fails. Fail closed, not open |
| Missing flag audit trail | No logging of flag evaluation for security decisions | MEDIUM | Log flag evaluations for security-relevant flags. Include user, flag, variation, timestamp |

**Remediation — Secure feature flag pattern:**
```typescript
// WRONG: auth behind feature flag
if (featureFlags.isEnabled('new-auth-flow')) {
  requireAuth(req);  // skipped when flag is off!
}

// RIGHT: security is unconditional, only implementation varies
requireAuth(req);  // always runs
if (featureFlags.isEnabled('new-auth-flow')) {
  useNewAuthProvider(req);
} else {
  useLegacyAuthProvider(req);
}
```

```python
# WRONG: client-controlled security decision
@app.route('/admin')
def admin():
    flags = request.headers.get('X-Feature-Flags', '{}')
    if json.loads(flags).get('admin_access'):  # attacker sets this header
        return admin_panel()

# RIGHT: server-side evaluation only
@app.route('/admin')
def admin():
    if flag_service.evaluate('admin_access', user_id=current_user.id):
        return admin_panel()
    return abort(403)
```

### Stale Flag Cleanup

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Dead code behind permanently-off flag | Code unreachable because flag is always off | MEDIUM | Remove the flag and the dead code. Dead code is a maintenance burden and potential confusion source |
| Dead code behind permanently-on flag | Code always executes but is still wrapped in flag check | LOW | Remove the flag wrapper. Make the code unconditional. Clean up the flag from the flag service |
| Flag referencing removed code | Flag evaluation for code that was deleted | LOW | Remove the flag definition from the flag service. Clean up dashboard |

## Pre-Release Security Gate

### Required Pre-Release Checks

| Check | Tool/Method | Severity if Skipped |
|-------|------------|-------------------|
| Secret scan | `detect-secrets`, `gitleaks`, `truffleHog` | CRITICAL |
| Dependency audit | `npm audit`, `pip-audit`, `govulncheck`, `trivy fs` | HIGH |
| SAST scan | `semgrep`, `gosec`, `bandit`, `eslint-plugin-security` | HIGH |
| Container image scan | `trivy image`, `grype` | HIGH |
| License compliance | `license-checker`, `pip-licenses`, `go-licenses` | MEDIUM |
| SBOM generation | `syft`, `cyclonedx-cli`, `spdx-sbom-generator` | MEDIUM |
| API contract validation | OpenAPI diff, contract tests | MEDIUM |
| Database migration test | Run migrations on staging copy, test rollback | HIGH |

**Remediation — Pre-release security gate (CI):**
```yaml
# .github/workflows/release-gate.yml
name: Release Security Gate
on:
  push:
    tags: ['v*']

permissions: read-all

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4
        with:
          fetch-depth: 0

      - name: Secret scan
        run: |
          pip install detect-secrets
          detect-secrets scan --all-files --baseline .secrets.baseline
          detect-secrets audit --report --baseline .secrets.baseline

      - name: Dependency audit
        run: npm audit --production --audit-level=high

      - name: SAST scan
        run: |
          pip install semgrep
          semgrep --config auto --error --severity ERROR .

      - name: Container scan
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          trivy fs --severity HIGH,CRITICAL --exit-code 1 .

      - name: License check
        run: npx license-checker --production --failOn "GPL-3.0;AGPL-3.0"

      - name: Generate SBOM
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft . -o cyclonedx-json > sbom.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

### Release Artifact Signing

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unsigned release artifacts | Binaries/containers published without signature | HIGH | Sign with cosign (containers), GPG (binaries), or Sigstore (keyless). Verify signatures in deployment pipeline |
| Missing provenance attestation | No SLSA provenance on release artifacts | MEDIUM | Use `slsa-framework/slsa-github-generator` to generate provenance. Attach to release |
| Missing SBOM | No software bill of materials for release | MEDIUM | Generate SBOM with `syft` or `cyclonedx-cli`. Attach to release. Required by many compliance frameworks |
| Signing key in repo | Code signing key committed to version control | CRITICAL | Remove key from repo immediately. Rotate signing key. Store in CI secret vault or HSM |

**Remediation — Container image signing with cosign:**
```bash
# Sign image after push
cosign sign --key cosign.key registry.example.com/app:v1.2.3

# Verify before deployment
cosign verify --key cosign.pub registry.example.com/app:v1.2.3

# Keyless signing with Sigstore (recommended)
cosign sign --yes registry.example.com/app:v1.2.3
cosign verify --certificate-identity=ci@example.com \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  registry.example.com/app:v1.2.3
```

### Deployment Approval Workflows

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Production deploy without approval | Automatic deployment to production on merge | HIGH | Use GitHub Environments with required reviewers. Require manual approval for production |
| Single-person approval | Only one reviewer required for production deploy | MEDIUM | Require 2+ reviewers for production deployments. Include at least one security-aware reviewer |
| No deployment audit trail | Deployments not logged with who/what/when | MEDIUM | Log all deployments: deployer, commit SHA, timestamp, environment. Use GitHub deployment API |
| Missing rollback plan | Deployment without documented rollback procedure | MEDIUM | Document rollback steps for every deployment. Test rollback in staging before production deploy |
