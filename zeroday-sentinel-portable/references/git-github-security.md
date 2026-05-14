# Git & GitHub Workflow Security Reference

Security checks for the entire Git/GitHub lifecycle — repository setup, authentication, branching, merging, rebasing, pushing, pulling, commit integrity, organization hardening, deploy keys, webhooks, and git configuration.

## Repository Setup & Access Control

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Public repo with sensitive code | Private/internal code in public repository | CRITICAL | Change visibility to private. Audit for leaked secrets. Rotate any exposed credentials |
| Forking enabled on private repo | `Allow forking` enabled on private repository | MEDIUM | Disable forking unless required. Forked repos retain data even if source is deleted |
| No branch protection on main | `main`/`master` without branch protection rules | HIGH | Enable branch protection: require PR reviews, status checks, and signed commits |
| Admin bypass on branch protection | `Do not allow bypassing the above settings` unchecked | HIGH | Enable for admins too. Bypass defeats the purpose of branch protection |
| Stale review dismissal disabled | Stale reviews not dismissed when new commits pushed | MEDIUM | Enable `Dismiss stale pull request approvals when new commits are pushed` |
| No CODEOWNERS enforcement | Missing CODEOWNERS or not required in branch protection | MEDIUM | Create CODEOWNERS file. Enable `Require review from Code Owners` in branch protection |
| Auto-delete head branches disabled | Merged branches accumulate | LOW | Enable `Automatically delete head branches` in repo settings |

**Remediation — Branch protection setup (GitHub CLI):**
```bash
gh api repos/{owner}/{repo}/branches/main/protection -X PUT \
  -f "required_pull_request_reviews[dismiss_stale_reviews]=true" \
  -f "required_pull_request_reviews[required_approving_review_count]=1" \
  -f "required_pull_request_reviews[require_code_owner_reviews]=true" \
  -f "required_status_checks[strict]=true" \
  -f "required_status_checks[contexts][]=ci/tests" \
  -f "required_status_checks[contexts][]=ci/security" \
  -f "enforce_admins=true" \
  -f "required_linear_history=false" \
  -f "allow_force_pushes=false" \
  -f "allow_deletions=false"
```

**Remediation — CODEOWNERS file:**
```
# .github/CODEOWNERS
* @org/engineering
/src/auth/ @org/security-team
/src/middleware/ @org/security-team
/.github/workflows/ @org/devops @org/security-team
/terraform/ @org/devops @org/security-team
Dockerfile @org/devops
*.tf @org/devops @org/security-team
```

## Authentication & Credentials

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No 2FA enforcement | Organization without required 2FA | HIGH | Enable `Require two-factor authentication` in org settings. Members without 2FA are removed |
| Classic PAT without expiration | Personal access token with no expiry | HIGH | Set expiration (max 90 days). Migrate to fine-grained PATs with repository-scoped access |
| Overly broad PAT scope | PAT with `repo`, `admin:org`, or `write:packages` when not needed | HIGH | Use fine-grained PATs scoped to specific repos and minimum permissions |
| Plaintext credential storage | `git config credential.helper store` (writes to `~/.git-credentials` in plaintext) | CRITICAL | Use secure helpers: `osxkeychain` (macOS), `libsecret`/`secretservice` (Linux), `manager` (Windows) |
| SSH key without passphrase | SSH key generated without passphrase protection | MEDIUM | Regenerate with passphrase: `ssh-keygen -t ed25519 -C "email" -a 100`. Use ssh-agent |
| RSA key with weak size | SSH key using RSA with <4096 bits | MEDIUM | Use Ed25519: `ssh-keygen -t ed25519`. If RSA required, use 4096 bits minimum |
| `.git-credentials` committed | Plaintext credential file in repository | CRITICAL | Remove from repo. Add to `.gitignore`. Rotate all credentials in the file. Use `git filter-repo` to purge history |
| OAuth app with excessive scope | GitHub OAuth app requesting `repo` scope for read-only needs | MEDIUM | Request minimum scopes. Use `public_repo` if only public repos needed. Prefer GitHub Apps over OAuth |

**Remediation — Secure credential helper setup:**
```bash
# macOS
git config --global credential.helper osxkeychain

# Linux (GNOME/KDE)
git config --global credential.helper libsecret
# OR
git config --global credential.helper /usr/lib/git-core/git-credential-libsecret

# Windows
git config --global credential.helper manager

# NEVER use 'store' — it writes plaintext to ~/.git-credentials
# git config --global credential.helper store  # INSECURE
```

**Remediation — Fine-grained PAT migration:**
```bash
# Check existing classic tokens
gh auth status

# Create fine-grained token (via GitHub UI):
# Settings → Developer settings → Fine-grained tokens
# - Set expiration (30-90 days)
# - Select only required repositories
# - Grant minimum permissions (e.g., Contents: Read, Pull requests: Write)
```

## Branch & Tag Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Force push to shared branch | `git push --force` to main/develop/release | CRITICAL | Use `--force-with-lease` instead. Enable `Do not allow force pushes` in branch protection |
| Unsigned commits on protected branch | Commits without GPG/SSH signature on main | MEDIUM | Enable `Require signed commits` in branch protection. Set up commit signing |
| Unsigned release tags | Tags created without GPG signature | MEDIUM | Sign tags: `git tag -s v1.0.0 -m "Release v1.0.0"`. Verify: `git tag -v v1.0.0` |
| Deleted branch with unmerged work | Force-deleting branch with unique commits | HIGH | Use `git branch -d` (safe delete, prevents unmerged deletion). Avoid `git branch -D` unless certain |
| Tag moved after publish | Existing tag deleted and recreated pointing to different commit | HIGH | Protect tags in branch protection settings. Moving tags breaks reproducibility and trust |
| No default branch protection | Protected branches don't include the default branch | HIGH | Always protect the default branch first. Use rulesets for consistent protection across branches |

**Remediation — Commit signing setup:**
```bash
# GPG signing
gpg --full-generate-key  # choose RSA 4096 or Ed25519
gpg --list-secret-keys --keyid-format=long
git config --global user.signingkey <KEY_ID>
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# SSH signing (simpler, recommended)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Verify a signed commit
git log --show-signature -1

# Add your public key to GitHub:
# Settings → SSH and GPG keys → New SSH/GPG key → Signing Key
```

## Merge, Rebase & Conflict Resolution

For merge conflict resolution in security-critical files, see [critical-workflows.md](critical-workflows.md) — Merge Conflict Resolution Security section.

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Rebase of shared/pushed history | `git rebase` on commits already pushed to shared branch | HIGH | Never rebase commits others have based work on. Use merge for shared branches. Rebase only local/unpushed commits |
| Interactive rebase dropping commits | `git rebase -i` with `drop` on commits containing security fixes | HIGH | Review dropped commits for security-relevant changes before completing rebase |
| `git reset --hard` without backup | Hard reset discarding uncommitted work | HIGH | Use `git stash` first, or create a backup branch: `git branch backup-$(date +%s)`. Check `git reflog` to recover |
| Merge without running tests | Merging branch without verifying CI passes | HIGH | Enable required status checks in branch protection. Never merge with failing checks |
| Squash merge hiding history | Squash merge obscuring individual commit context | LOW | Prefer regular merge for security-sensitive changes — preserves full review trail. Note in PR description if squashing |
| Stash containing secrets | Sensitive data in `git stash` entries | MEDIUM | Run `git stash list` and `git stash show -p` to audit stash contents. Drop stashes with secrets: `git stash drop` |
| Detached HEAD with uncommitted work | Working in detached HEAD state with unsaved changes | MEDIUM | Create a branch: `git switch -c recovery-branch`. Never checkout another branch with uncommitted detached HEAD work |

**Remediation — Safe rebase workflow:**
```bash
# SAFE: rebase local/unpushed commits
git fetch origin
git rebase origin/main  # only if your commits haven't been pushed

# SAFE: interactive rebase of unpushed work
git rebase -i origin/main  # squash/reorder only unpushed commits

# DANGEROUS: never do this on shared branches
# git rebase -i HEAD~5  # if any of these are pushed, DON'T
# git push --force       # NEVER force push to shared branches

# SAFER force push (prevents overwriting others' work)
git push --force-with-lease  # fails if remote has new commits you don't have
```

**Remediation — Recovery from accidental reset:**
```bash
# Find lost commits in reflog
git reflog

# Recover a specific commit
git checkout <commit-sha>
git switch -c recovery-branch

# Undo a git reset --hard (within reflog retention period)
git reset --hard HEAD@{1}  # go back one reflog entry
```

## Push & Pull Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Pushing to main directly | Direct push to main/master without PR | HIGH | Enable branch protection requiring PRs. Use feature branches: `git switch -c feature/name` |
| Clone over HTTP (not HTTPS/SSH) | `git clone http://` (unencrypted) | HIGH | Always use HTTPS or SSH: `git clone git@github.com:org/repo.git`. Configure SSH: `gh auth setup-git` |
| Submodule from untrusted source | `.gitmodules` referencing external/untrusted repository | HIGH | Audit all submodule sources. Pin to specific commits. Prefer vendoring for critical dependencies |
| Shallow clone in CI for security scanning | `git clone --depth 1` used before secret scanning | MEDIUM | Use full clone for secret scanning — shallow clones miss historical secrets. Use `--depth 1` only for builds |
| Mirror with write access | Mirror pushing to a public fork | HIGH | Mirrors should be read-only. Verify mirror target is appropriate. Don't mirror private repos to public |
| Pull without verifying remote | Pulling from unverified remote (typosquatted org name) | HIGH | Verify remote URL: `git remote -v`. Use SSH with verified host keys |

**Remediation — Secure repository cloning:**
```bash
# Preferred: SSH (authenticated, encrypted)
git clone git@github.com:org/repo.git

# Alternative: HTTPS (use credential helper, not inline creds)
git clone https://github.com/org/repo.git
# NEVER: git clone https://user:token@github.com/org/repo.git

# Verify remote after clone
git remote -v
# origin  git@github.com:org/repo.git (fetch)
# origin  git@github.com:org/repo.git (push)

# Audit submodules
git submodule status
cat .gitmodules  # verify all URLs are trusted
```

## Commit History Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Author spoofing | `user.name` or `user.email` set to another person's identity | MEDIUM | Require signed commits (branch protection). Signed commits verify the author's identity via GPG/SSH key |
| Commit message injection | Commit messages containing shell metacharacters parsed by CI | MEDIUM | Never interpolate commit messages in shell commands. Pass through environment variables (same as PR title injection) |
| Secret in commit history | Secret committed then "removed" in later commit (still in history) | CRITICAL | Rotate secret immediately. Use `git filter-repo` or BFG to purge from history. See [secret-detection.md](secret-detection.md) |
| Squash to hide malicious change | Multiple commits squashed to obscure a security-weakening change | LOW | Review squash merge diffs as carefully as regular merges. Compare the squashed diff against the original PR commits |
| Unverified merge commits | Merge commits from unsigned contributors | LOW | Enable `Require signed commits` for merge commits. Verify committer identity on sensitive branches |

**Remediation — Purge secret from git history:**
```bash
# Option 1: git filter-repo (recommended)
pip install git-filter-repo
git filter-repo --invert-paths --path config/secrets.yaml

# Option 2: BFG Repo-Cleaner (for large repos)
java -jar bfg.jar --replace-text passwords.txt repo.git
cd repo.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# After purging: force push all branches
git push --force-with-lease --all
git push --force-with-lease --tags

# CRITICAL: rotate the exposed secret regardless — history purging
# is defense-in-depth, not a substitute for rotation
```

## GitHub Organization Hardening

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| 2FA not required | Organization not enforcing two-factor authentication | HIGH | Settings → Authentication security → Require two-factor authentication. Non-compliant members are removed |
| Base permissions too broad | Default repository permission is `Write` or `Admin` | HIGH | Set base permissions to `No permission` or `Read`. Grant write access per-team |
| Owner count too low | Single organization owner | HIGH | Have at least 2 org owners for redundancy. Store recovery codes securely |
| Owner count too high | More than 3-5 organization owners | MEDIUM | Limit owners to 2-5. Use team-based admin roles instead of org owner |
| Outside collaborators unreviewed | External collaborators with access to private repos | MEDIUM | Audit outside collaborators quarterly. Remove inactive ones. Prefer team membership over individual invites |
| Audit log not monitored | No alerting on security-relevant org events | MEDIUM | Monitor audit log for: member role changes, repository visibility changes, branch protection changes, SSH key additions |
| No IP allow list | Organization accessible from any IP | LOW | Configure IP allow list for org if using GitHub Enterprise Cloud. Restrict to corporate VPN/office IPs |
| SAML SSO not configured | Enterprise org without SSO | MEDIUM | Enable SAML SSO for enterprise orgs. Enforces identity provider authentication |

**Remediation — Org security audit checklist:**
```bash
# Check org members and their 2FA status
gh api orgs/{org}/members --jq '.[].login'

# List outside collaborators
gh api orgs/{org}/outside_collaborators --jq '.[].login'

# Check repository visibility
gh repo list {org} --json name,visibility --jq '.[] | "\(.name): \(.visibility)"'

# Audit recent security events (Enterprise only)
gh api orgs/{org}/audit-log --jq '.[].action' | sort | uniq -c | sort -rn
```

## Deploy Keys, Webhooks & GitHub Apps

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Deploy key with write access | Deploy key has push (write) permissions | HIGH | Recreate as read-only unless writes are strictly necessary. Each repo should have its own deploy key |
| Deploy key shared across repos | Same SSH key used as deploy key in multiple repos | HIGH | Generate unique deploy key per repository. Shared keys increase blast radius |
| Webhook without secret | Webhook configured without `secret` field (no payload signature) | HIGH | Set webhook secret. Verify `X-Hub-Signature-256` header on every delivery. Reject unsigned payloads |
| Webhook over HTTP | Webhook payload URL using `http://` | HIGH | Use HTTPS for all webhook endpoints. Webhook payloads may contain sensitive data |
| GitHub App with excessive permissions | App requesting `Administration`, `Organization`, or `Contents: Write` unnecessarily | MEDIUM | Review app permissions. Grant minimum required. Prefer `Contents: Read` over `Write` where possible |
| Long-lived GitHub App token | App installation token not refreshed | MEDIUM | Installation tokens expire after 1 hour by default. Don't cache them beyond expiry. Use on-demand token generation |

**Remediation — Webhook secret validation (Node.js):**
```javascript
const crypto = require('crypto');

function verifyWebhookSignature(payload, signature, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  const digest = 'sha256=' + hmac.update(payload).digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(digest),
    Buffer.from(signature)
  );
}

// In your webhook handler
app.post('/webhook', (req, res) => {
  const signature = req.headers['x-hub-signature-256'];
  if (!signature || !verifyWebhookSignature(req.rawBody, signature, WEBHOOK_SECRET)) {
    return res.status(401).send('Invalid signature');
  }
  // Process webhook...
});
```

**Remediation — Webhook secret validation (Python):**
```python
import hmac
import hashlib

def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = 'sha256=' + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# In your webhook handler
@app.post("/webhook")
async def webhook(request: Request):
    signature = request.headers.get("X-Hub-Signature-256", "")
    body = await request.body()
    if not verify_webhook_signature(body, signature, WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid signature")
    # Process webhook...
```

## Git Configuration Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| `credential.helper store` | Credentials stored in plaintext at `~/.git-credentials` | CRITICAL | Switch to secure helper: `osxkeychain`, `libsecret`, or `manager`. Delete `~/.git-credentials` |
| Missing `user.email` verification | Git config email doesn't match GitHub verified email | LOW | Set correct email: `git config --global user.email "you@company.com"`. Add to GitHub verified emails |
| Global `.gitignore` missing secret patterns | No global gitignore or missing `*.pem`, `*.key`, `.env` | MEDIUM | Create global gitignore: `git config --global core.excludesfile ~/.gitignore_global` |
| Pre-commit hooks disabled project-wide | No `.pre-commit-config.yaml` or husky setup | MEDIUM | Install pre-commit hooks for secret scanning and linting. Use `pre-commit`, `husky`, or `lefthook` |
| `http.sslVerify false` | TLS verification disabled in git config | CRITICAL | Remove: `git config --global --unset http.sslVerify`. Fix the underlying certificate issue instead |
| `core.autocrlf` inconsistency | Mixed line endings causing diff noise that hides real changes | LOW | Standardize: `git config --global core.autocrlf input` (Unix) or use `.gitattributes` |
| Git aliases hiding dangerous commands | Alias that runs `push --force` or `reset --hard` without flags | MEDIUM | Audit aliases: `git config --global --get-regexp alias`. Replace dangerous aliases with safe alternatives |

**Remediation — Secure `.gitconfig` template:**
```ini
[user]
    name = Your Name
    email = you@company.com
    signingkey = ~/.ssh/id_ed25519.pub

[commit]
    gpgsign = true

[tag]
    gpgsign = true

[gpg]
    format = ssh

[credential]
    helper = osxkeychain  # macOS (or libsecret for Linux)

[core]
    excludesfile = ~/.gitignore_global
    autocrlf = input

[push]
    default = current
    autoSetupRemote = true

[pull]
    rebase = true

[fetch]
    prune = true

[init]
    defaultBranch = main

# Safety aliases
[alias]
    pushf = push --force-with-lease  # safer force push
    unstage = reset HEAD --          # safe unstage
    undo = reset --soft HEAD^        # undo commit, keep changes
```

**Remediation — Global `.gitignore_global`:**
```
# Secrets and credentials
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
.htpasswd
credentials.*
secrets.*
service-account-key.json
.git-credentials

# IDE and OS
.idea/
.vscode/settings.json
*.swp
.DS_Store
Thumbs.db
```

**Remediation — Pre-commit hook setup:**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: no-commit-to-branch
        args: ['--branch', 'main', '--branch', 'master']

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```
