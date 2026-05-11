# Infrastructure & IaC Security Reference

Detailed checks for Terraform, ArgoCD, Helm, and other infrastructure-as-code files.

## Terraform Security Checks

### IAM & Access Control

| Check | Pattern | Severity |
|-------|---------|----------|
| Wildcard actions | `"Action": "*"` or `"Action": ["*"]` | CRITICAL |
| Wildcard resources | `"Resource": "*"` with non-read actions | HIGH |
| Missing condition constraints | `assume_role_policy` without `Condition` block | MEDIUM |
| Overly broad principals | `"Principal": "*"` or `"Principal": {"AWS": "*"}` | CRITICAL |
| Inline policies over managed | Large inline `policy` blocks vs `aws_iam_policy_attachment` | LOW |
| PassRole without constraints | `iam:PassRole` without resource scoping | HIGH |

**Grep patterns:**
```
"Action"\s*:\s*"\*"
"Resource"\s*:\s*"\*"
"Principal"\s*:\s*"\*"
iam:PassRole
```

### Network Exposure

| Check | Pattern | Severity |
|-------|---------|----------|
| Open ingress to world | `cidr_blocks = ["0.0.0.0/0"]` on non-443/80 ports | HIGH |
| Open egress to world | Egress `0.0.0.0/0` without justification | MEDIUM |
| Missing VPC endpoints | S3/DynamoDB access without `aws_vpc_endpoint` | MEDIUM |
| Public subnets for internal resources | `map_public_ip_on_launch = true` for non-public workloads | HIGH |
| SSH open to world | Port 22 with `0.0.0.0/0` CIDR | CRITICAL |
| RDP open to world | Port 3389 with `0.0.0.0/0` CIDR | CRITICAL |

### Encryption

| Check | Pattern | Severity |
|-------|---------|----------|
| Unencrypted EBS volumes | `aws_ebs_volume` without `encrypted = true` | HIGH |
| Unencrypted RDS | `aws_db_instance` without `storage_encrypted = true` | HIGH |
| S3 without encryption | `aws_s3_bucket` without server-side encryption config | HIGH |
| Missing KMS key rotation | `aws_kms_key` without `enable_key_rotation = true` | MEDIUM |
| Unencrypted Elasticache | `aws_elasticache_replication_group` without `at_rest_encryption_enabled` | HIGH |

### S3 Bucket Security

| Check | Pattern | Severity |
|-------|---------|----------|
| Public access not blocked | Missing `aws_s3_bucket_public_access_block` | HIGH |
| ACL set to public | `acl = "public-read"` or `"public-read-write"` | CRITICAL |
| Missing bucket logging | No `logging` configuration | MEDIUM |
| Missing versioning | No `versioning { enabled = true }` for state/data buckets | MEDIUM |

### State & Secrets

| Check | Pattern | Severity |
|-------|---------|----------|
| Hardcoded secrets in .tf | `password =`, `secret =`, `api_key =` with literal values | CRITICAL |
| Remote state without encryption | `backend "s3"` without `encrypt = true` | HIGH |
| Sensitive outputs unmasked | `output` blocks without `sensitive = true` for credentials | HIGH |
| .tfvars with secrets | Credential values in committed `.tfvars` files | CRITICAL |

## ArgoCD Security Checks

| Check | Pattern | Severity |
|-------|---------|----------|
| Cluster-admin RBAC | `policy.csv` granting `*` on all resources | CRITICAL |
| Plaintext secrets in Application manifests | Secret values in `spec.source.helm.parameters` | CRITICAL |
| Auto-sync without prune protection | `automated.prune: true` without safeguards | MEDIUM |
| Unknown/external repos | `spec.source.repoURL` pointing to untrusted sources | HIGH |

## Helm Chart Security Checks

| Check | Pattern | Severity |
|-------|---------|----------|
| Secrets in values.yaml | Plaintext passwords, tokens, keys in default values | CRITICAL |
| Tiller-era patterns | `tiller` references (Helm 2 security anti-pattern) | MEDIUM |
| Missing network policies | No `NetworkPolicy` template in chart | MEDIUM |
| Hardcoded image tags | `image.tag` defaulting to `latest` | MEDIUM |

## Compliance Touchpoints

These are not full compliance checks but patterns that indicate potential compliance issues:

| Framework | Relevant Checks |
|-----------|----------------|
| CIS AWS Foundations | IAM root access, CloudTrail logging, VPC flow logs |
| PCI-DSS | Encryption at rest and in transit, access logging, network segmentation |
| SOC 2 | Access controls, encryption, audit logging |

Flag these as informational when detected — full compliance scanning is out of scope.
