# Container & Kubernetes Security Reference

Security checks for Dockerfiles, container configurations, Kubernetes manifests, and Helm templates.

## Dockerfile Security

### Image & Build Security

| Check | Pattern | Severity |
|-------|---------|----------|
| Unpinned base image | `FROM image` or `FROM image:latest` | MEDIUM |
| No digest pinning for critical images | `FROM image:tag` without `@sha256:` for production | LOW |
| Running as root | No `USER` instruction or `USER root` as final stage | HIGH |
| ADD instead of COPY | `ADD` for local files (ADD has tar extraction and URL fetch side effects) | MEDIUM |
| Secrets in build args | `ARG PASSWORD`, `ARG API_KEY`, `ARG TOKEN` | CRITICAL |
| Secrets in ENV | `ENV PASSWORD=`, `ENV SECRET_KEY=` with literal values | CRITICAL |
| Secrets in COPY | Copying `.env`, `credentials`, `*.pem`, `*.key` files | HIGH |
| Package manager cache | `apt-get install` without `rm -rf /var/lib/apt/lists/*` | LOW |
| Missing HEALTHCHECK | No `HEALTHCHECK` instruction | LOW |

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

| Check | Pattern | Severity |
|-------|---------|----------|
| Dev tools in final image | `gcc`, `make`, `curl`, `wget` installed but not in build stage | MEDIUM |
| Debug tools in final image | `strace`, `gdb`, `tcpdump` in final stage | MEDIUM |
| Unnecessary COPY from build | Copying build artifacts that include source code | LOW |

### Containerfile Best Practices

| Check | Description | Severity |
|-------|-------------|----------|
| COPY --chown | Use `COPY --chown=user:group` instead of `RUN chown` after COPY | LOW |
| Writable root filesystem | No indication of read-only root fs intent | MEDIUM |
| Excessive layers | More than 15 RUN instructions that could be combined | LOW |
| SHELL instruction | Using SHELL to change to a less secure shell | MEDIUM |

## Kubernetes Manifest Security

### Pod Security

| Check | Pattern | Severity |
|-------|---------|----------|
| Privileged containers | `securityContext.privileged: true` | CRITICAL |
| Running as root | Missing `runAsNonRoot: true` or `runAsUser: 0` | HIGH |
| Writable root filesystem | Missing `readOnlyRootFilesystem: true` | MEDIUM |
| All capabilities | `capabilities.add: ["ALL"]` | CRITICAL |
| Dangerous capabilities | `add: ["SYS_ADMIN"]`, `add: ["NET_ADMIN"]` without justification | HIGH |
| Missing capability drops | No `capabilities.drop: ["ALL"]` | MEDIUM |
| Host network | `hostNetwork: true` | HIGH |
| Host PID | `hostPID: true` | HIGH |
| Host IPC | `hostIPC: true` | HIGH |
| hostPath volumes | `hostPath` volume mounts (especially `/`, `/etc`, `/var/run/docker.sock`) | CRITICAL |
| Docker socket mount | Mounting `/var/run/docker.sock` | CRITICAL |

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

### Resource Controls

| Check | Pattern | Severity |
|-------|---------|----------|
| Missing resource limits | No `resources.limits` (CPU and/or memory) | MEDIUM |
| Missing resource requests | No `resources.requests` | LOW |
| Excessive resource limits | Memory limits > 8Gi or CPU limits > 4 without justification | LOW |
| Missing LimitRange | Namespace without LimitRange (if deploying namespace configs) | LOW |

### RBAC Security

| Check | Pattern | Severity |
|-------|---------|----------|
| Cluster-admin binding | `ClusterRoleBinding` to `cluster-admin` | CRITICAL |
| Wildcard verbs | `verbs: ["*"]` in Role/ClusterRole | HIGH |
| Wildcard resources | `resources: ["*"]` in Role/ClusterRole | HIGH |
| Wildcard API groups | `apiGroups: ["*"]` in Role/ClusterRole | HIGH |
| Secrets access | `resources: ["secrets"]` with `verbs: ["get", "list"]` broadly scoped | MEDIUM |
| Escalation privileges | `verbs: ["escalate"]` or `verbs: ["bind"]` | HIGH |
| Service account token auto-mount | Missing `automountServiceAccountToken: false` | LOW |

**Grep patterns:**
```
kind:\s*ClusterRoleBinding
cluster-admin
verbs:\s*\["\*"\]
resources:\s*\["\*"\]
apiGroups:\s*\["\*"\]
```

### Network Security

| Check | Pattern | Severity |
|-------|---------|----------|
| Missing NetworkPolicy | No NetworkPolicy for the namespace/workload | MEDIUM |
| Allow-all ingress | NetworkPolicy with empty `ingress` (allows all) | HIGH |
| Allow-all egress | NetworkPolicy with empty `egress` (allows all) | MEDIUM |
| External service exposure | `Service` type `LoadBalancer` or `NodePort` without justification | MEDIUM |
| Missing Ingress TLS | `Ingress` without `tls` section | HIGH |

### Service Mesh & mTLS

| Check | Pattern | Severity |
|-------|---------|----------|
| mTLS disabled | `PeerAuthentication` with `DISABLE` mode | HIGH |
| Permissive mTLS | `PeerAuthentication` with `PERMISSIVE` mode in production | MEDIUM |
| Sidecar bypass | `sidecar.istio.io/inject: "false"` without justification | MEDIUM |

## Helm Chart Security

### Values Security

| Check | Pattern | Severity |
|-------|---------|----------|
| Default passwords | `password:`, `secret:`, `token:` with non-empty default values | CRITICAL |
| Image tag latest | `image.tag` defaulting to `latest` or empty | MEDIUM |
| Privileged by default | `securityContext.privileged` defaulting to `true` | CRITICAL |
| Root by default | `securityContext.runAsUser` defaulting to `0` | HIGH |

### Chart Dependencies

| Check | Pattern | Severity |
|-------|---------|----------|
| Unpinned chart versions | `version: "*"` or missing version in Chart.yaml dependencies | MEDIUM |
| Untrusted repositories | Dependencies from non-official Helm repos | MEDIUM |
| Missing Chart.lock | Dependencies defined but no Chart.lock committed | MEDIUM |

## OpenShift-Specific Checks

| Check | Pattern | Severity |
|-------|---------|----------|
| SecurityContextConstraints | Custom SCCs granting excessive privileges | HIGH |
| anyuid SCC | SCC allowing `RunAsAny` for user strategy | HIGH |
| Route without TLS | `Route` without `tls.termination` | HIGH |
| Missing OAuth proxy | Web-facing services without authentication proxy | MEDIUM |
