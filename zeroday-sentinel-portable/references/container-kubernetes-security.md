# Container & Kubernetes Security Reference

Security checks for Dockerfiles, container configurations, Kubernetes manifests, and Helm templates.

## Dockerfile Security

### Image & Build Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unpinned base image | `FROM image` or `FROM image:latest` | MEDIUM | Pin to specific version: `FROM node:20.11.0-slim`. For maximum security, pin to digest: `FROM node@sha256:abc...` |
| No digest pinning for critical images | `FROM image:tag` without `@sha256:` for production | LOW | Add digest: `FROM node:20.11.0@sha256:abc...`. Get digest with `docker manifest inspect` |
| Running as root | No `USER` instruction or `USER root` as final stage | HIGH | Add non-root user: `RUN addgroup -S app && adduser -S app -G app` then `USER app` before `ENTRYPOINT` |
| ADD instead of COPY | `ADD` for local files (ADD has tar extraction and URL fetch side effects) | MEDIUM | Replace `ADD` with `COPY` for local files. Only use `ADD` for tar auto-extraction |
| Secrets in build args | `ARG PASSWORD`, `ARG API_KEY`, `ARG TOKEN` | CRITICAL | Use BuildKit secrets: `RUN --mount=type=secret,id=api_key cat /run/secrets/api_key`. Or use multi-stage builds where secrets only exist in build stage |
| Secrets in ENV | `ENV PASSWORD=`, `ENV SECRET_KEY=` with literal values | CRITICAL | Pass secrets at runtime: `docker run -e PASSWORD="$PASSWORD"`. Never bake secrets into image layers |
| Secrets in COPY | Copying `.env`, `credentials`, `*.pem`, `*.key` files | HIGH | Add to `.dockerignore`. Use runtime volume mounts or secret managers for credentials |
| Package manager cache | `apt-get install` without `rm -rf /var/lib/apt/lists/*` | LOW | Chain in one RUN: `RUN apt-get update && apt-get install -y pkg && rm -rf /var/lib/apt/lists/*` |
| Missing HEALTHCHECK | No `HEALTHCHECK` instruction | LOW | Add: `HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health \|\| exit 1` |

**Grep patterns for Dockerfiles:**
```
^FROM\s+\S+\s*$
^FROM\s+\S+:latest
^ADD\s+(?!https?://)
^ARG\s+.*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)
^ENV\s+.*(PASSWORD|SECRET|TOKEN|KEY)=
USER\s+root\s*$
```

### Multi-Stage Build Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Dev tools in final image | `gcc`, `make`, `curl`, `wget` installed but not in build stage | MEDIUM | Use multi-stage builds. Install dev tools only in `AS build` stage. Copy only artifacts to final stage |
| Debug tools in final image | `strace`, `gdb`, `tcpdump` in final stage | MEDIUM | Remove debug tools from final image. Use ephemeral debug containers in Kubernetes instead |
| Unnecessary COPY from build | Copying build artifacts that include source code | LOW | Copy only compiled output: `COPY --from=build /app/dist ./dist` not `COPY --from=build /app .` |

### Containerfile Best Practices

| Check | Description | Severity | Remediation |
|-------|-------------|----------|-------------|
| COPY --chown | Use `COPY --chown=user:group` instead of `RUN chown` after COPY | LOW | Replace `COPY . . && RUN chown -R app:app .` with `COPY --chown=app:app . .` |
| Writable root filesystem | No indication of read-only root fs intent | MEDIUM | Use read-only root fs in K8s: `readOnlyRootFilesystem: true`. Mount writable `/tmp` as emptyDir |
| Excessive layers | More than 15 RUN instructions that could be combined | LOW | Combine related RUN instructions with `&&`. Each RUN creates a layer |
| SHELL instruction | Using SHELL to change to a less secure shell | MEDIUM | Keep default shell. If custom shell needed, ensure it's a hardened alternative |

**Container scanning setup:**
```bash
# Trivy (comprehensive scanner)
trivy image --severity HIGH,CRITICAL myapp:latest

# Hadolint (Dockerfile linter)
hadolint Dockerfile

# Add to CI
# docker build -t myapp . && trivy image myapp:latest --exit-code 1 --severity HIGH,CRITICAL
```

## Kubernetes Manifest Security

### Pod Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Privileged containers | `securityContext.privileged: true` | CRITICAL | Remove `privileged: true`. Use specific capabilities instead if needed |
| Running as root | Missing `runAsNonRoot: true` or `runAsUser: 0` | HIGH | Add `securityContext: { runAsNonRoot: true, runAsUser: 1000 }` |
| Writable root filesystem | Missing `readOnlyRootFilesystem: true` | MEDIUM | Add `securityContext: { readOnlyRootFilesystem: true }`. Mount writable dirs as emptyDir volumes |
| All capabilities | `capabilities.add: ["ALL"]` | CRITICAL | Drop all and add only what's needed: `capabilities: { drop: ["ALL"], add: ["NET_BIND_SERVICE"] }` |
| Dangerous capabilities | `add: ["SYS_ADMIN"]`, `add: ["NET_ADMIN"]` without justification | HIGH | Remove unless absolutely required. Document justification. Use Pod Security Standards to enforce |
| Missing capability drops | No `capabilities.drop: ["ALL"]` | MEDIUM | Add `securityContext: { capabilities: { drop: ["ALL"] } }` to all containers |
| Host network | `hostNetwork: true` | HIGH | Remove `hostNetwork`. Use Services and Ingress for network exposure |
| Host PID | `hostPID: true` | HIGH | Remove `hostPID`. If monitoring is needed, use dedicated monitoring agents |
| Host IPC | `hostIPC: true` | HIGH | Remove `hostIPC`. Use K8s native inter-container communication |
| hostPath volumes | `hostPath` volume mounts (especially `/`, `/etc`, `/var/run/docker.sock`) | CRITICAL | Replace with emptyDir, PVCs, or ConfigMaps. Never mount host filesystem |
| Docker socket mount | Mounting `/var/run/docker.sock` | CRITICAL | Use Kaniko, Buildkit, or Podman for in-cluster builds instead of Docker socket |

**Grep patterns:**
```
privileged:\s*true
hostNetwork:\s*true
hostPID:\s*true
hostIPC:\s*true
hostPath:
/var/run/docker.sock
capabilities:
runAsUser:\s*0
```

**Recommended security context for all workloads:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

### Resource Controls

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing resource limits | No `resources.limits` (CPU and/or memory) | MEDIUM | Add limits: `resources: { limits: { memory: "512Mi", cpu: "500m" }, requests: { memory: "256Mi", cpu: "250m" } }` |
| Missing resource requests | No `resources.requests` | LOW | Add requests matching typical usage. Requests affect scheduling, limits prevent noisy neighbors |
| Excessive resource limits | Memory limits > 8Gi or CPU limits > 4 without justification | LOW | Right-size based on actual usage from metrics. Start small and increase based on monitoring |
| Missing LimitRange | Namespace without LimitRange (if deploying namespace configs) | LOW | Add LimitRange to set default limits for pods without explicit resources |

### RBAC Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Cluster-admin binding | `ClusterRoleBinding` to `cluster-admin` | CRITICAL | Create custom ClusterRole with minimum permissions. Never bind cluster-admin to application service accounts |
| Wildcard verbs | `verbs: ["*"]` in Role/ClusterRole | HIGH | List specific verbs needed: `verbs: ["get", "list", "watch"]` |
| Wildcard resources | `resources: ["*"]` in Role/ClusterRole | HIGH | List specific resources: `resources: ["pods", "services"]` |
| Wildcard API groups | `apiGroups: ["*"]` in Role/ClusterRole | HIGH | List specific API groups: `apiGroups: ["", "apps"]` |
| Secrets access | `resources: ["secrets"]` with `verbs: ["get", "list"]` broadly scoped | MEDIUM | Scope secrets access to specific namespaces with Role (not ClusterRole). Use `resourceNames` to restrict to specific secrets |
| Escalation privileges | `verbs: ["escalate"]` or `verbs: ["bind"]` | HIGH | Remove unless required for cluster operators. These allow privilege escalation |
| Service account token auto-mount | Missing `automountServiceAccountToken: false` | LOW | Add `automountServiceAccountToken: false` to pods that don't need K8s API access |

### Network Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing NetworkPolicy | No NetworkPolicy for the namespace/workload | MEDIUM | Create default-deny NetworkPolicy, then allow specific traffic. Start with `ingress: []` (deny all) |
| Allow-all ingress | NetworkPolicy with empty `ingress` (allows all) | HIGH | Add specific ingress rules with podSelector and namespaceSelector |
| Allow-all egress | NetworkPolicy with empty `egress` (allows all) | MEDIUM | Restrict egress to required endpoints. Allow DNS (port 53) and specific service IPs |
| External service exposure | `Service` type `LoadBalancer` or `NodePort` without justification | MEDIUM | Use ClusterIP with Ingress controller. Use internal LoadBalancer for private access |
| Missing Ingress TLS | `Ingress` without `tls` section | HIGH | Add TLS: `tls: [{hosts: ["app.example.com"], secretName: app-tls}]`. Use cert-manager for auto-renewal |

### Service Mesh & mTLS

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| mTLS disabled | `PeerAuthentication` with `DISABLE` mode | HIGH | Set `mode: STRICT` for production namespaces |
| Permissive mTLS | `PeerAuthentication` with `PERMISSIVE` mode in production | MEDIUM | Migrate to STRICT after verifying all clients support mTLS |
| Sidecar bypass | `sidecar.istio.io/inject: "false"` without justification | MEDIUM | Remove bypass annotation. If required, document justification and add compensating controls |

## Helm Chart Security

### Values Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Default passwords | `password:`, `secret:`, `token:` with non-empty default values | CRITICAL | Set defaults to empty string. Use `required` in templates. Inject secrets via `--set` or external secret operator |
| Image tag latest | `image.tag` defaulting to `latest` or empty | MEDIUM | Default to specific version. Use `.Chart.AppVersion` as default |
| Privileged by default | `securityContext.privileged` defaulting to `true` | CRITICAL | Default to `false`. Require explicit opt-in with documentation of why |
| Root by default | `securityContext.runAsUser` defaulting to `0` | HIGH | Default to `1000`. Set `runAsNonRoot: true` |

### Chart Dependencies

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unpinned chart versions | `version: "*"` or missing version in Chart.yaml dependencies | MEDIUM | Pin to specific versions: `version: "1.2.3"`. Run `helm dependency update` to generate Chart.lock |
| Untrusted repositories | Dependencies from non-official Helm repos | MEDIUM | Use official repos (bitnami, stable). Verify chart source and maintainer. Mirror charts to internal registry |
| Missing Chart.lock | Dependencies defined but no Chart.lock committed | MEDIUM | Run `helm dependency build` and commit `Chart.lock` |

## OpenShift-Specific Checks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| SecurityContextConstraints | Custom SCCs granting excessive privileges | HIGH | Use `restricted` SCC when possible. Create custom SCCs with minimum required privileges |
| anyuid SCC | SCC allowing `RunAsAny` for user strategy | HIGH | Use `MustRunAsRange` or `MustRunAsNonRoot`. Only allow anyuid for verified requirements |
| Route without TLS | `Route` without `tls.termination` | HIGH | Add `tls: { termination: edge }` or `termination: reencrypt` for end-to-end TLS |
| Missing OAuth proxy | Web-facing services without authentication proxy | MEDIUM | Deploy OAuth proxy sidecar for authentication. Use OpenShift OAuth or external IdP |
