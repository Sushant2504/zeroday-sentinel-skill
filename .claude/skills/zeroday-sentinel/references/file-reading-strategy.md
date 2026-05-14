# File Reading Strategy Reference

Governs which files groundwork reads, in what order, and what to skip. Designed to maximize analysis quality within practical context limits.

## Always Skip

These paths are never read during groundwork analysis — they are generated, vendored, or binary content with no analytical value.

| Pattern | Reason |
|---------|--------|
| `node_modules/` | Vendored dependencies |
| `vendor/` | Vendored dependencies (Go, PHP, Ruby) |
| `.git/` | Git internals |
| `dist/`, `build/`, `out/` | Build output |
| `target/` | Rust/Java build output |
| `__pycache__/`, `*.pyc` | Python bytecode |
| `.venv/`, `.tox/`, `env/`, `venv/` | Virtual environments |
| `.next/`, `.nuxt/`, `.svelte-kit/` | Framework build cache |
| `coverage/`, `.nyc_output/` | Test coverage output |
| `*.min.js`, `*.min.css` | Minified files |
| `*.map` (source maps) | Generated mappings |
| `*.generated.*`, `*.pb.go`, `*_pb2.py` | Generated code |
| `swagger-ui/`, `redoc/` | Generated API docs |
| `*.wasm`, `*.class`, `*.o`, `*.so`, `*.dylib` | Compiled binaries |
| `*.png`, `*.jpg`, `*.gif`, `*.ico`, `*.woff*` | Binary assets (use find-images.sh instead) |
| `*.sqlite`, `*.db` | Database files |

### Lock Files — Read Manifests Instead

| Skip (lock) | Read Instead (manifest) |
|-------------|------------------------|
| `package-lock.json` | `package.json` |
| `yarn.lock` | `package.json` |
| `pnpm-lock.yaml` | `package.json` |
| `Cargo.lock` | `Cargo.toml` |
| `go.sum` | `go.mod` |
| `Gemfile.lock` | `Gemfile` |
| `uv.lock`, `Pipfile.lock` | `requirements.txt`, `pyproject.toml`, `Pipfile` |
| `pubspec.lock` | `pubspec.yaml` |
| `Podfile.lock` | `Podfile` |
| `composer.lock` | `composer.json` |
| `.terraform.lock.hcl` | `*.tf` files |
| `Chart.lock` | `Chart.yaml` |

## Priority Read Order

Read files in this order to build understanding from entry points outward.

### Priority 1: Entry Points & Configuration

| Pattern | What It Reveals |
|---------|----------------|
| `main.*`, `app.*`, `index.*`, `server.*` | Application entry point and initialization |
| `cmd/` directory | Go CLI/service entry points |
| `manage.py` | Django management entry |
| `settings.*`, `config.*`, `*.config.*` | Application configuration shape |
| `.env.example`, `.env.sample` | Environment variable requirements |
| Root `*.yaml`, `*.toml`, `*.json` | Project-level configuration |

### Priority 2: Routing & API Definitions

| Pattern | What It Reveals |
|---------|----------------|
| `routes/`, `router/`, `urls.py` | Request routing and endpoint definitions |
| `api/`, `handlers/`, `controllers/` | API implementation |
| `openapi.*`, `swagger.*`, `*.api.yaml` | API specifications |
| `middleware/` | Request/response pipeline |
| `graphql/`, `schema.graphql`, `*.gql` | GraphQL schema and resolvers |

### Priority 3: Models, Schema & Auth

| Pattern | What It Reveals |
|---------|----------------|
| `models/`, `entities/`, `schema/` | Data model definitions |
| `migrations/`, `migrate/` | Schema evolution history |
| `*.sql` (non-migration) | Raw queries, stored procedures |
| `auth/`, `security/`, `middleware/auth*` | Authentication and authorization logic |
| `permissions/`, `policies/`, `rbac/` | Access control definitions |

### Priority 4: Core Business Logic

| Pattern | What It Reveals |
|---------|----------------|
| `services/`, `domain/`, `core/`, `lib/` | Business logic implementation |
| `internal/`, `pkg/` | Go internal/shared packages |
| `utils/`, `helpers/`, `common/` | Shared utilities |
| `workers/`, `jobs/`, `tasks/`, `queues/` | Background processing |

### Priority 5: Infrastructure & DevOps

| Pattern | What It Reveals |
|---------|----------------|
| `Dockerfile`, `Containerfile` | Container build and runtime config |
| `docker-compose*` | Multi-container orchestration |
| `*.tf`, `*.tfvars` | Infrastructure as code |
| `Chart.yaml`, `templates/` (Helm) | Kubernetes deployment templates |
| `k8s/`, `kubernetes/`, `deploy/` | Kubernetes manifests |
| `.github/workflows/`, `Jenkinsfile` | CI/CD pipeline definitions |

### Priority 6: Tests

| Pattern | What It Reveals |
|---------|----------------|
| `*_test.*`, `*.test.*`, `*.spec.*` | Test patterns and coverage approach |
| `test/`, `tests/`, `__tests__/`, `spec/` | Test organization |
| `fixtures/`, `testdata/`, `mocks/` | Test infrastructure |
| `conftest.py`, `jest.config.*` | Test framework configuration |

### Priority 7: Documentation

| Pattern | What It Reveals |
|---------|----------------|
| `README*`, `CONTRIBUTING*`, `CHANGELOG*` | Project documentation |
| `docs/`, `documentation/`, `wiki/` | Extended documentation |
| `ARCHITECTURE.md`, `DESIGN.md` | Design decisions |
| `adr/`, `ADR/`, `decisions/` | Architecture Decision Records |

## Size Limits

| Constraint | Limit | Rationale |
|------------|-------|-----------|
| Max files for deep reading | 200 per project | Context budget — prioritize by read order |
| Skip individual files over | 5,000 lines | Likely generated or data dumps |
| For files over 500 lines | Read first 200 + last 50 | Understand structure and exports |
| Total line budget per project | ~50,000 lines | Practical context limit |
| Max single-read batch | 20 files | Avoid context flooding per agent |

## Framework-Specific Read Patterns

When a framework is detected, reorder the read queue to prioritize framework-critical files.

### Django
`settings.py` → `urls.py` → `models.py` → `views.py` → `serializers.py` → `admin.py` → `forms.py` → `signals.py` → `middleware.py` → `management/commands/`

### FastAPI / Flask
`main.py` or `app.py` → `routers/` or `routes/` → `models/` → `schemas/` → `dependencies.py` → `middleware.py` → `config.py`

### React / Next.js
`App.*` or `_app.*` → `pages/` or `app/` → `routes.*` → `store/` or `context/` → `hooks/` → `components/` (top-level) → `api/` (Next.js API routes)

### Express.js / Nest.js
`app.*` or `server.*` → `routes/` → `controllers/` → `middleware/` → `models/` → `services/` → `config/`

### Go (standard layout)
`main.go` → `cmd/` → `internal/` → `pkg/` → `api/` → `models/` or `domain/` → `middleware/` → `config/`

### Spring Boot
`*Application.java` → `*Controller.java` → `*Service.java` → `*Repository.java` → `*Entity.java` → `*Config.java` → `*Filter.java`

### Rails
`config/routes.rb` → `app/models/` → `app/controllers/` → `app/services/` → `config/initializers/` → `db/migrate/` → `config/application.rb`

### Rust (Actix/Axum)
`main.rs` → `lib.rs` → `routes/` or `handlers/` → `models/` → `middleware/` → `config/` → `schema.rs`
