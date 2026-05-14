# Contributing to Zero-Day Sentinel

Thank you for your interest in improving Zero-Day Sentinel. This guide explains the project structure, how to add or modify security domains, and how to submit quality contributions.

## Project Structure

```
.claude/skills/zeroday-sentinel/
├── SKILL.md                          # Main skill definition (entry point)
├── references/                       # Domain-specific security check documents
│   ├── web-security.md
│   ├── api-security.md
│   ├── application-security.md
│   ├── authentication-authorization.md
│   ├── database-security.md
│   ├── performance-security.md
│   ├── infrastructure-security.md
│   ├── container-kubernetes-security.md
│   ├── cicd-pipeline-security.md
│   ├── secret-detection.md
│   ├── supply-chain-analysis.md
│   ├── mobile-security.md
│   ├── cloud-native-security.md
│   ├── agent-skill-security.md
│   ├── critical-workflows.md
│   ├── git-github-security.md
│   ├── remediation-playbooks.md      # Step-by-step fix guides for every category
│   └── report-template.md            # Output format, severity definitions, category taxonomy
└── samples/
    └── sample-report.md              # Example scan output

.cursor/rules/                        # Cursor IDE replica (condensed versions)
├── zeroday-sentinel.mdc              # Master rule (alwaysApply: true)
├── <domain>-security.mdc             # One .mdc file per domain
└── ...
```

**How the pieces fit together:**

1. `SKILL.md` is the entry point. It defines the scan workflow, domain detection table, and inline always-check patterns.
2. Each `references/<domain>.md` file contains the detailed check tables, code examples, and remediation guidance for one security domain.
3. `SKILL.md` loads reference documents on-demand based on which files are detected in the scan scope.
4. `remediation-playbooks.md` provides step-by-step fix guides referenced by the report.
5. `report-template.md` defines the output format and the full category taxonomy.
6. `.cursor/rules/*.mdc` files are condensed, passive versions of the references for Cursor IDE.

## Types of Contributions

### Adding a New Security Domain

This is the most impactful type of contribution. To add domain #N:

**1. Create the reference document:** `references/<domain-name>.md`

Follow the existing format:

```markdown
# <Domain Name> Security Reference

<One-sentence description of what this document covers.>

## <Section Name>

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| <what to look for> | <code pattern or config> | CRITICAL/HIGH/MEDIUM/LOW | <how to fix> |

**Remediation — <specific fix>:**
\```<language>
// Before (vulnerable)
<bad code>

// After (fixed)
<good code>
\```
```

Requirements:
- Every check table row must have a **Remediation** column
- Include at least one full code example per section (before/after)
- Use the standard severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Cover at least 3 sections with 3+ checks each

**2. Update `SKILL.md`:**

- Add a row to the **Domain Detection** table with trigger patterns and reference link
- Update the domain count in the **Scope** section
- Add relevant file patterns to the **Risk Categorization** table if needed

**3. Add remediation playbooks:** `references/remediation-playbooks.md`

Add at least 2 playbooks for the most critical finding categories in your domain. Each playbook must follow the 4-step format:

```markdown
### Playbook: <Finding Title>

**Step 1 — Immediate Fix:**
<code-level change with before/after>

**Step 2 — Verify:**
<test commands + expected output>

**Step 3 — Prevent:**
<linting rules, CI checks, pre-commit hooks>

**Step 4 — Harden:**
<defense-in-depth, monitoring, architectural changes>
```

Also add entries to the **Quick Reference: Fix by Category** table at the bottom.

**4. Update `references/report-template.md`:**

Add your domain's categories to the **Category Taxonomy** section:

```markdown
### <Domain> Categories

- `<Domain> - <Subcategory 1>`
- `<Domain> - <Subcategory 2>`
```

**5. Add sample findings:** `samples/sample-report.md`

Add at least 1-2 example findings from your domain to the sample report. Update the summary counts.

**6. Create the Cursor rule:** `.cursor/rules/<domain-name>.mdc`

```markdown
---
description: "<One-line description of the rules>"
globs: ["<glob patterns for relevant files>"]
---

# <Domain Name> Security

<Condensed version of the check tables and rules — no full code examples,
just the key patterns and never/always rules>
```

**7. Update `README.md`:**

- Increment the domain count
- Add row to the domain table
- Add file to the file structure tree

**8. Update `.cursor/rules/zeroday-sentinel.mdc`:**

- Add the domain name to the description

### Adding Checks to an Existing Domain

1. Add rows to the relevant check table in `references/<domain>.md`
2. If adding a new section, include at least one remediation code example
3. Add the new category to `references/report-template.md` taxonomy if it's a new subcategory
4. Add a remediation playbook if the finding is CRITICAL or HIGH

### Improving Remediation Guidance

1. Add or improve code examples in `references/<domain>.md` — always show before/after
2. Add full playbooks to `references/remediation-playbooks.md` for uncovered categories
3. Include verification commands that developers can actually run
4. Add prevention steps (linting rules, CI checks, pre-commit hooks)

### Fixing Errors or Outdated Patterns

1. Update the pattern or guidance in the relevant reference document
2. If a check is no longer relevant, remove it with a note in your PR description
3. Update any affected Cursor `.mdc` files to stay in sync

## Code Style and Conventions

### Reference Documents

- Use **tables** for check patterns: `| Check | Pattern | Severity | Remediation |`
- Every table row must include a **Remediation** column with a concise fix
- Full remediation code examples go below the table with `**Remediation — <title>:**` heading
- Always show **before (vulnerable)** and **after (fixed)** code
- Use standard severity levels consistently:
  - **CRITICAL** — exploitable with immediate risk (credential exposure, injection, auth bypass)
  - **HIGH** — likely exploitable (missing auth, overly permissive IAM, command injection vector)
  - **MEDIUM** — defense-in-depth gap (unpinned images, missing encryption, missing headers)
  - **LOW** — minor hardening (verbose errors, missing HEALTHCHECK)

### Category Naming

Follow the `Domain - Subcategory` format:
- `Web - Cross-Site Scripting (XSS)`
- `Database - SQL Injection`
- `Git - Force Push to Protected Branch`
- `GitHub - Branch Protection Gap`

### Cursor Rules (.mdc files)

- Keep condensed — no full code examples, just the key rules
- Use **never/always** imperative style
- Set appropriate `globs` to minimize context loading
- Only `zeroday-sentinel.mdc` should have `alwaysApply: true`

### Writing Style

- Be direct and specific — "Set `debuggable false` in release build type" not "Consider disabling debug mode"
- Use **never** and **always** for absolute rules
- Include the exact config key, function name, or CLI flag
- Don't explain why security matters in general — explain the specific impact of this specific check

## Testing Your Changes

Before submitting:

1. **Verify file references:** All links in `SKILL.md` point to existing files
2. **Check category consistency:** Categories in your reference match the taxonomy in `report-template.md`
3. **Validate severity levels:** CRITICAL/HIGH/MEDIUM/LOW used consistently
4. **Run the skill:** Invoke `/zeroday-sentinel` in a project containing the file types your domain covers — verify your checks are triggered
5. **Check Cursor sync:** If you modified a reference, verify the corresponding `.mdc` file reflects the key changes

## Submitting a Pull Request

1. Fork the repository and create a feature branch
2. Make your changes following the conventions above
3. Write a clear PR description explaining:
   - What domain or checks you're adding/modifying
   - Why the checks matter (link to CVEs, OWASP references, or real-world incidents if applicable)
   - How you tested the changes
4. Ensure all files that need updating are updated (use the checklist in "Adding a New Security Domain")

### PR Checklist

For new domains:
- [ ] Reference document created in `references/`
- [ ] Domain added to `SKILL.md` detection table
- [ ] Domain count updated in `SKILL.md` scope section
- [ ] Remediation playbooks added (at least 2)
- [ ] Categories added to `report-template.md` taxonomy
- [ ] Sample findings added to `samples/sample-report.md`
- [ ] Cursor `.mdc` file created
- [ ] `README.md` updated (domain count, table, file structure)
- [ ] `zeroday-sentinel.mdc` description updated

For new checks in existing domains:
- [ ] Check rows added to reference table
- [ ] Remediation code example included (for HIGH/CRITICAL)
- [ ] Category added to `report-template.md` if new subcategory
- [ ] Cursor `.mdc` file updated if key rule added

## Questions?

Open an issue to discuss before starting work on a large contribution. This helps avoid duplicate effort and ensures alignment with the project's direction.
