# Cloud Native Security Reference

Security checks for AWS, GCP, Azure services, serverless functions, managed databases, object storage, and cloud-native architectures.

## AWS Security

### IAM

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Root account usage | Code using root account credentials | CRITICAL | Create IAM users/roles. Enable MFA on root. Use root only for billing and account-level changes |
| Long-lived access keys | `AKIA*` keys in code or config | CRITICAL | Use IAM roles with temporary credentials (STS). Use OIDC federation for CI/CD |
| Overly permissive policies | `"Action": "*"` or `"Resource": "*"` | HIGH | Follow least privilege. Use IAM Access Analyzer to right-size permissions. Start with zero permissions and add as needed |
| Missing condition keys | Policies without condition constraints | MEDIUM | Add conditions: `aws:SourceIp`, `aws:PrincipalOrgID`, `aws:RequestedRegion` |
| Cross-account trust without ExternalId | AssumeRole without `sts:ExternalId` condition | HIGH | Require ExternalId in cross-account trust policies to prevent confused deputy attacks |

**Remediation — Least-privilege IAM policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject"
    ],
    "Resource": "arn:aws:s3:::my-bucket/uploads/*",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalOrgID": "o-1234567890"
      }
    }
  }]
}
```

### S3

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Public bucket | `acl: "public-read"` or missing public access block | CRITICAL | Enable S3 Block Public Access at account level. Use bucket policies for specific access |
| Missing encryption | No server-side encryption configured | HIGH | Enable SSE-S3 (default) or SSE-KMS. Enable bucket default encryption |
| Missing access logging | No S3 access logging configured | MEDIUM | Enable server access logging to a separate logging bucket |
| Missing versioning | Versioning not enabled on data buckets | MEDIUM | Enable versioning on buckets containing important data. Add lifecycle rules for old versions |
| Overly permissive bucket policy | `"Principal": "*"` in bucket policy | CRITICAL | Restrict principals to specific accounts/roles. Use VPC endpoints for private access |

### Lambda / Serverless

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Secrets in environment variables | Plaintext secrets in Lambda env vars | HIGH | Use AWS Secrets Manager or SSM Parameter Store. Reference secrets at runtime, not deploy time |
| Overly permissive execution role | Lambda with `AdministratorAccess` | CRITICAL | Create function-specific IAM roles with minimum permissions. Use one role per function |
| Missing VPC for data access | Lambda accessing databases outside VPC | HIGH | Place Lambdas in VPC when accessing private resources. Use VPC endpoints for AWS services |
| No reserved concurrency | Lambda without concurrency limits (cost/DoS risk) | HIGH | Set reserved concurrency based on expected load. Prevents cost explosion from attack traffic |
| Missing input validation | Lambda handler without event validation | HIGH | Validate event schema. Use Powertools for validation. Reject malformed events early |
| Cold start auth bypass | Auth middleware failing during cold start | HIGH | Initialize auth before handler registration. Use provisioned concurrency for critical auth functions |

**Remediation — Secure Lambda function (Python):**
```python
import json
import boto3
from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities.validation import validate

logger = Logger()
tracer = Tracer()

# Load secrets from Secrets Manager (cached across invocations)
secrets_client = boto3.client('secretsmanager')
_db_secret = None

def get_db_secret():
    global _db_secret
    if _db_secret is None:
        response = secrets_client.get_secret_value(SecretId='prod/db/credentials')
        _db_secret = json.loads(response['SecretString'])
    return _db_secret

@logger.inject_lambda_context
@tracer.capture_lambda_handler
def handler(event, context):
    # Validate input
    validate(event=event, schema=INPUT_SCHEMA)

    # Use secrets from Secrets Manager
    db_creds = get_db_secret()
    # ...process...
```

### Other AWS Services

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| SQS without encryption | SQS queue without SSE | MEDIUM | Enable SQS SSE with KMS or SQS-managed keys |
| SNS without encryption | SNS topic without encryption | MEDIUM | Enable SNS SSE. Restrict publish/subscribe to specific principals |
| DynamoDB without encryption | DynamoDB table without encryption at rest | MEDIUM | Enable encryption (default since 2023, verify for older tables) |
| CloudWatch logs without encryption | Log groups without KMS encryption | LOW | Enable KMS encryption for log groups containing sensitive data |
| RDS publicly accessible | `publicly_accessible: true` on RDS instance | CRITICAL | Set `publicly_accessible: false`. Use VPC private subnets. Access via VPN/bastion |
| ElastiCache without auth | Redis/Memcached without authentication | HIGH | Enable AUTH token for Redis. Use IAM auth for Redis 7+. Place in private subnet |

## GCP Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Service account key in code | JSON service account key file committed | CRITICAL | Use Workload Identity Federation. Delete the key file. Rotate compromised keys |
| Overly permissive IAM | `roles/owner` or `roles/editor` on service accounts | HIGH | Use predefined roles with minimum permissions. Create custom roles for specific needs |
| Public Cloud Storage bucket | `allUsers` or `allAuthenticatedUsers` access | CRITICAL | Remove public access. Use Uniform bucket-level access. Set organization policy to prevent public access |
| Cloud Functions without auth | HTTP functions without authentication | HIGH | Require authentication: `--no-allow-unauthenticated`. Use IAM invoker role |
| Cloud SQL without SSL | Database connections without SSL enforcement | HIGH | Enforce SSL connections. Use Cloud SQL Proxy for secure connections |
| Missing VPC Service Controls | Sensitive APIs accessible outside perimeter | MEDIUM | Create VPC Service Controls perimeter for sensitive projects |
| Firewall rules allowing 0.0.0.0/0 | VPC firewall open to all IPs | HIGH | Restrict source IPs to known ranges. Use service accounts for internal service communication |

**Remediation — GCP Workload Identity (replacing service account keys):**
```yaml
# GitHub Actions workflow
jobs:
  deploy:
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: 'projects/123/locations/global/workloadIdentityPools/github/providers/my-repo'
          service_account: 'deploy@project.iam.gserviceaccount.com'
```

## Azure Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Client secret in code | Azure AD client secret hardcoded | CRITICAL | Use Managed Identity for Azure resources. Use certificate-based auth for external apps |
| Storage account public access | Blob container with public access | CRITICAL | Disable public access at storage account level. Use SAS tokens or Managed Identity |
| Missing Key Vault usage | Secrets in app settings instead of Key Vault | HIGH | Store secrets in Azure Key Vault. Reference from app settings with `@Microsoft.KeyVault(SecretUri=...)` |
| SQL Database with public endpoint | Azure SQL without private endpoint | HIGH | Use Private Link/Private Endpoint. Disable public network access |
| NSG allowing all inbound | Network Security Group with `0.0.0.0/0` inbound | HIGH | Restrict inbound rules to specific source IPs/subnets. Use Application Security Groups |
| Missing diagnostic settings | No diagnostic logging on critical resources | MEDIUM | Enable diagnostic settings. Send logs to Log Analytics workspace. Set up alerts |

## Serverless Framework Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| `*` in IAM statements | `serverless.yml` with `iamRoleStatements: [{ Effect: Allow, Action: *, Resource: * }]` | CRITICAL | Specify exact actions and resources per function |
| Environment variables with secrets | Secrets in `serverless.yml` environment section | HIGH | Use `${ssm:/path/to/secret}` or `${env:VAR}` with CI/CD secrets |
| Missing API Gateway authorization | HTTP endpoints without authorizer | HIGH | Add Lambda authorizer or Cognito user pool authorizer to all endpoints |
| Missing CORS restrictions | `cors: true` (allows all origins) | MEDIUM | Specify allowed origins: `cors: { origins: ['https://app.example.com'] }` |
| Verbose error responses | Default Lambda error responses exposing stack traces | MEDIUM | Custom error handler that returns generic messages. Log detailed errors server-side |

## Container Registry Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Public container registry | ECR/GCR/ACR with public access | HIGH | Use private registries. Enable image scanning. Restrict pull access to specific IAM roles |
| Missing image scanning | No vulnerability scanning on pushed images | MEDIUM | Enable automatic scanning: ECR scan on push, GCR Container Analysis, ACR Defender |
| Missing image signing | Images not signed before deployment | MEDIUM | Sign images with cosign/Notation. Verify signatures in admission controller |
| Stale images in registry | Images not cleaned up (cost and stale vulnerability risk) | LOW | Implement lifecycle policies: keep last N tags, delete untagged after 7 days |

## Infrastructure as Code (Pulumi/CDK/Terraform)

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Hardcoded secrets in IaC | Secret values in Pulumi/CDK/Terraform code | CRITICAL | Use secret managers: `pulumi.secret()`, `cdk.SecretValue.secretsManager()`, `data.aws_secretsmanager_secret` |
| State file with secrets | Terraform state containing plaintext secrets | HIGH | Use remote state with encryption. Enable state locking. Restrict state access |
| Missing drift detection | No mechanism to detect infrastructure drift | MEDIUM | Run `terraform plan` in CI. Use AWS Config rules or equivalent for drift detection |
| Missing tagging | Resources without ownership/environment tags | LOW | Enforce tagging policies. Require at minimum: `environment`, `team`, `service` tags |
