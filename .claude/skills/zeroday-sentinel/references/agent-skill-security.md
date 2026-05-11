# Agent & Skill Definition Security Reference

Security checks specific to Claude Code agent definitions, skill files, MCP server configurations, and plugin manifests.

## SKILL.md Security Checks

### Tool Access

| Check | Pattern | Severity |
|-------|---------|----------|
| Unrestricted Bash | `allowed-tools` includes `Bash` without command scoping | HIGH |
| Write access when unnecessary | `allowed-tools` includes `Write` or `Edit` for read-only analysis skills | MEDIUM |
| Agent tool access | `allowed-tools` includes `Agent` — can spawn unrestricted sub-agents | HIGH |
| All tools granted | `allowed-tools` not specified (defaults to all tools) | HIGH |
| WebSearch for non-research skills | `allowed-tools` includes `WebSearch` for skills that shouldn't need internet | LOW |

**Recommended pattern for read-only skills:**
```yaml
allowed-tools: [Read, Grep, Glob]
```

**For skills needing controlled Bash:**
```yaml
allowed-tools: [Read, Grep, Glob, Bash(git diff *), Bash(git log *)]
```

### Instruction Injection Risks

| Check | Description | Severity |
|-------|-------------|----------|
| User input in tool calls | Skill instructions that pass user input directly into Bash commands without validation | HIGH |
| Dynamic file path construction | Building file paths from user-provided values without sanitization | MEDIUM |
| Unvalidated URL fetches | Using WebFetch with URLs derived from user input or file content | HIGH |
| Template injection | Skill constructs prompts/commands from external data without escaping | MEDIUM |

**Example of vulnerable pattern:**
```markdown
Run this command with the user's cluster name:
\`\`\`bash
oc login --cluster=$CLUSTER_NAME
\`\`\`
```

**Safe alternative:**
```markdown
First validate the cluster name matches expected format (alphanumeric, hyphens only).
Then run: `oc login --cluster=<validated-cluster-name>`
```

### Privilege Boundaries

| Check | Description | Severity |
|-------|-------------|----------|
| Elevation commands | Skills that execute `sudo`, `ocm-backplane elevate`, or similar without requiring user confirmation | CRITICAL |
| Destructive operations | Skills that delete resources, force-push, or reset without safeguards | HIGH |
| Missing confirmation gates | Dangerous operations without explicit "STOP and ask user" instructions | HIGH |
| Scope creep | Skill instructions that go beyond its stated purpose (e.g., a "read-only diagnostic" skill that also applies fixes) | MEDIUM |

## Agent Definition Security

### Agent Configuration

| Check | Pattern | Severity |
|-------|---------|----------|
| Overly broad tool list | `tools:` including write/execute tools not needed for the agent's purpose | HIGH |
| Missing model constraints | No `model:` field — may default to most expensive/powerful model unnecessarily | LOW |
| Excessive sub-agent spawning | Agent instructions encouraging spawning many sub-agents without limits | MEDIUM |
| Missing safety guardrails | Agent instructions without explicit "do NOT" constraints | MEDIUM |

### Agent Orchestration Risks

| Check | Description | Severity |
|-------|-------------|----------|
| Unbounded loops | Agent instructions that could create infinite loops of tool calls | HIGH |
| Recursive agent spawning | Agent that spawns sub-agents which spawn more sub-agents | MEDIUM |
| Data exfiltration paths | Agent with both Read and WebFetch/WebSearch — could read local files and send data externally | HIGH |
| Cross-trust-boundary operations | Agent that reads from untrusted sources and writes to trusted locations | HIGH |

## MCP Server Security

### .mcp.json Configuration

| Check | Pattern | Severity |
|-------|---------|----------|
| Untrusted MCP endpoints | `url` pointing to non-organizational domains | HIGH |
| HTTP endpoints | `url` using `http://` instead of `https://` | HIGH |
| Hardcoded credentials | API keys or tokens in `.mcp.json` | CRITICAL |
| Overly broad tool grants | MCP server providing tools that exceed the plugin's purpose | MEDIUM |
| Missing authentication | MCP endpoint without authentication mechanism | HIGH |

**Check pattern:**
```
grep -E '"url"\s*:\s*"http://' .mcp.json
grep -E '(token|key|password|secret)' .mcp.json
```

### MCP Tool Verification

| Check | Description | Severity |
|-------|-------------|----------|
| Tool name collisions | MCP tools that shadow built-in Claude tools | HIGH |
| Excessive permissions | MCP tools that can write/delete when only read is needed | MEDIUM |
| Missing tool descriptions | Tools without clear descriptions of what they do and what data they access | LOW |
| Data flow concerns | MCP tools that send local data to external services | MEDIUM |

## Plugin Manifest Security

### plugin.json Checks

| Check | Pattern | Severity |
|-------|---------|----------|
| Version format | Non-semver version strings that could confuse update checks | LOW |
| Author impersonation | Author name impersonating official teams without being one | MEDIUM |
| Description mismatch | Plugin description claiming capabilities not present in skills/agents | LOW |

### Marketplace Registration

| Check | Pattern | Severity |
|-------|---------|----------|
| External source trust | Marketplace entries with `source.type: "github"` pointing to unverified repos | HIGH |
| Missing OWNERS | Plugin without OWNERS file — no clear accountability | MEDIUM |
| Inconsistent naming | Marketplace `name` doesn't match `plugin.json` `name` | MEDIUM |

## Reference Document Trust

### Content Safety

| Check | Description | Severity |
|-------|-------------|----------|
| Executable instructions in references | Reference docs containing commands that Claude might execute verbatim | MEDIUM |
| External URLs in references | References linking to external resources that could change | LOW |
| Conflicting instructions | Reference docs that contradict SKILL.md safety constraints | HIGH |
| Hidden instructions | Reference docs containing prompt injection attempts disguised as documentation | CRITICAL |

### Review Guidance

When reviewing reference documents:
1. Verify all bash commands are read-only unless the skill explicitly requires write access
2. Check that no reference document overrides safety constraints from SKILL.md
3. Ensure URLs point to known, trusted domains
4. Look for instructions that could cause the agent to behave unexpectedly
