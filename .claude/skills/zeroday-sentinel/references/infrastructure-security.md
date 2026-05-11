# Infrastructure & IaC Security Reference

Detailed checks for Terraform, ArgoCD, Helm, and other infrastructure-as-code files.

## Terraform Security Checks

### IAM & Access Control

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Wildcard actions | `"Action": "*"` or `"Action": ["*"]` | CRITICAL | Replace with specific actions needed: `"Action": ["s3:GetObject", "s3:PutObject"]`. Use IAM Access Analyzer to right-size |
| Wildcard resources | `"Resource": "*"` with non-read actions | HIGH | Scope to specific ARNs: `"Resource": "arn:aws:s3:::my-bucket/*"` |
| Missing condition constraints | `assume_role_policy` without `Condition` block | MEDIUM | Add conditions: `"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-xxx"}}` |
| Overly broad principals | `"Principal": "*"` or `"Principal": {"AWS": "*"}` | CRITICAL | Restrict to specific accounts/roles: `"Principal": {"AWS": "arn:aws:iam::123:role/app"}` |
| Inline policies over managed | Large inline `policy` blocks vs `aws_iam_policy_attachment` | LOW | Extract to managed policies with `aws_iam_policy`. Easier to audit, reuse, and track |
| PassRole without constraints | `iam:PassRole` without resource scoping | HIGH | Restrict PassRole to specific role ARNs: `"Resource": "arn:aws:iam::*:role/specific-role"` |

**Grep patterns:**
```
"Action"\s*:\s*"\*"
"Resource"\s*:\s*"\*"
"Principal"\s*:\s*"\*"
iam:PassRole
```

**IaC scanning setup:**
```bash
# tfsec (now part of Trivy)
trivy config --severity HIGH,CRITICAL .

# checkov
pip install checkov
checkov -d . --framework terraform

# Add to CI
# GitHub Actions:
# - uses: aquasecurity/trivy-action@master
#   with:
#     scan-type: config
#     severity: HIGH,CRITICAL
```

### Network Exposure

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Open ingress to world | `cidr_blocks = ["0.0.0.0/0"]` on non-443/80 ports | HIGH | Restrict to known IP ranges: `cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12"]`. Use security group references for internal traffic |
| Open egress to world | Egress `0.0.0.0/0` without justification | MEDIUM | Restrict egress to required destinations. Use VPC endpoints for AWS services |
| Missing VPC endpoints | S3/DynamoDB access without `aws_vpc_endpoint` | MEDIUM | Create VPC endpoints: `aws_vpc_endpoint` with type `Gateway` for S3/DynamoDB |
| Public subnets for internal resources | `map_public_ip_on_launch = true` for non-public workloads | HIGH | Use private subnets for internal workloads. Route through NAT gateway for internet access |
| SSH open to world | Port 22 with `0.0.0.0/0` CIDR | CRITICAL | Remove SSH access. Use SSM Session Manager or bastion hosts with restricted IPs |
| RDP open to world | Port 3389 with `0.0.0.0/0` CIDR | CRITICAL | Remove RDP access. Use VPN or AWS Systems Manager for remote access |

### Encryption

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unencrypted EBS volumes | `aws_ebs_volume` without `encrypted = true` | HIGH | Add `encrypted = true`. Enable account-level default encryption: `aws_ebs_encryption_by_default` |
| Unencrypted RDS | `aws_db_instance` without `storage_encrypted = true` | HIGH | Add `storage_encrypted = true`. Use KMS CMK for cross-account access |
| S3 without encryption | `aws_s3_bucket` without server-side encryption config | HIGH | Add `aws_s3_bucket_server_side_encryption_configuration` with `sse_algorithm = "aws:kms"` |
| Missing KMS key rotation | `aws_kms_key` without `enable_key_rotation = true` | MEDIUM | Add `enable_key_rotation = true` to all KMS key resources |
| Unencrypted Elasticache | `aws_elasticache_replication_group` without `at_rest_encryption_enabled` | HIGH | Add `at_rest_encryption_enabled = true` and `transit_encryption_enabled = true` |

### S3 Bucket Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Public access not blocked | Missing `aws_s3_bucket_public_access_block` | HIGH | Add public access block with all four settings set to `true`. Enable at account level via S3 settings |
| ACL set to public | `acl = "public-read"` or `"public-read-write"` | CRITICAL | Remove public ACL. Use bucket policies for controlled access. Use CloudFront for public content |
| Missing bucket logging | No `logging` configuration | MEDIUM | Add `aws_s3_bucket_logging` targeting a dedicated logging bucket |
| Missing versioning | No `versioning { enabled = true }` for state/data buckets | MEDIUM | Add `aws_s3_bucket_versioning` with `status = "Enabled"`. Add lifecycle rules for old versions |

### State & Secrets

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Hardcoded secrets in .tf | `password =`, `secret =`, `api_key =` with literal values | CRITICAL | Use `variable` with no default. Pass via `TF_VAR_*` env vars or `-var-file`. Use `data.aws_secretsmanager_secret_version` |
| Remote state without encryption | `backend "s3"` without `encrypt = true` | HIGH | Add `encrypt = true` to backend config. Use KMS key for encryption |
| Sensitive outputs unmasked | `output` blocks without `sensitive = true` for credentials | HIGH | Add `sensitive = true` to outputs containing secrets. Terraform will mask the value in logs |
| .tfvars with secrets | Credential values in committed `.tfvars` files | CRITICAL | Add `*.tfvars` to `.gitignore`. Use `TF_VAR_*` environment variables instead |

## ArgoCD Security Checks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Cluster-admin RBAC | `policy.csv` granting `*` on all resources | CRITICAL | Scope to specific projects and resources: `p, role:dev, applications, *, dev-project/*, allow` |
| Plaintext secrets in Application manifests | Secret values in `spec.source.helm.parameters` | CRITICAL | Use SealedSecrets, External Secrets Operator, or Vault. Never put secrets in ArgoCD Application manifests |
| Auto-sync without prune protection | `automated.prune: true` without safeguards | MEDIUM | Add `automated.selfHeal: true` with `syncOptions: [PrunePropagationPolicy=foreground]`. Use sync windows for production |
| Unknown/external repos | `spec.source.repoURL` pointing to untrusted sources | HIGH | Restrict allowed repos in ArgoCD settings. Use organization's Git server only |

## Helm Chart Security Checks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Secrets in values.yaml | Plaintext passwords, tokens, keys in default values | CRITICAL | Remove default secrets. Use external secret injection. Document required secrets in values schema |
| Tiller-era patterns | `tiller` references (Helm 2 security anti-pattern) | MEDIUM | Migrate to Helm 3. Remove all Tiller references and RBAC |
| Missing network policies | No `NetworkPolicy` template in chart | MEDIUM | Add NetworkPolicy template with configurable ingress/egress rules |
| Hardcoded image tags | `image.tag` defaulting to `latest` | MEDIUM | Default to a specific version in `values.yaml`. Use `appVersion` from `Chart.yaml` |

## Compliance Touchpoints

| Framework | Relevant Checks | Remediation |
|-----------|----------------|-------------|
| CIS AWS Foundations | IAM root access, CloudTrail logging, VPC flow logs | Enable CloudTrail in all regions. Enable VPC flow logs. Disable root access keys |
| PCI-DSS | Encryption at rest and in transit, access logging, network segmentation | Encrypt all data stores. Enable TLS everywhere. Segment cardholder data environment |
| SOC 2 | Access controls, encryption, audit logging | Implement RBAC. Enable CloudTrail. Set up change management process |

Flag these as informational when detected — full compliance scanning is out of scope.
