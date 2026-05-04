# Acme Health Capstone Write-up

**Primary framework: HIPAA Security Rule.** Acme Health is a 50-person telehealth company; the Patient Intake API is squarely in scope for PHI under 45 CFR 160.103. HIPAA is the most direct fit for the workload, and every gap in the starter maps cleanly to a 164.x technical safeguard. We treat all 164.312 specifications labelled "addressable" as required, which is the industry-consensus reading and what HIPAA auditors expect to see defended.

OSCAL catalog cited as `control-implementation.source`: **NIST SP 800-66 Rev. 2** (Implementing the HIPAA Security Rule). HIPAA itself has no official OSCAL catalog; 800-66 Rev. 2 is the standard cite, with 164.x section IDs carried as `props` on each implemented requirement.

## Design decisions

### D-01: Two CMKs, not one shared workload key

We provision two customer-managed KMS keys with distinct trust boundaries:

- `aws_kms_key.app` protects PHI workload data (S3 uploads bucket, DynamoDB submissions table). The Lambda runtime role has `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey` on this key.
- `aws_kms_key.evidence` protects audit artifacts in the evidence vault (Layer 1). The Lambda role has *no* access. Pipeline-generated bundles are encrypted under this key by the GitHub Actions OIDC role, and read by a verifier role.

**Why two keys.** A single shared CMK lets one incident compromise both PHI and the audit chain of custody. If an attacker pops the Lambda, we want PHI exposure to be contained and the audit log to remain trustworthy evidence of what happened. Separate keys per trust boundary is the standard pattern for this. Cost is minimal (AWS charges roughly $1/month per CMK).

**Trade-off accepted.** Two keys means two key policies to maintain, two rotation states to monitor, and two sets of CloudTrail events to filter when investigating. Acceptable; the blast-radius reduction outweighs the operational cost.

### D-02: KMS deletion window of 30 days

Both CMKs use the maximum `deletion_window_in_days = 30`. A deleted key cannot be recovered after the window closes, which means PHI encrypted under it becomes permanently unreadable. The 30-day window provides the longest possible reconsideration period at no incremental cost.

### D-03: Hardening pattern depends on what the AWS provider exposes

The capstone aims to keep the starter file (`terraform/main.tf`) recognizable so a grader can diff against the upstream and see exactly what we added. We follow that rule where the AWS provider lets us, and break it where it doesn't.

- **Sibling-resource overrides** (preferred). When AWS exposes a configuration as its own Terraform resource, we add it as a sibling in a new file. Examples: `aws_s3_bucket_server_side_encryption_configuration` for GAP-01, `aws_s3_bucket_versioning` for GAP-04 (later), `aws_s3_bucket_policy` for GAP-03 (later). Starter file untouched.
- **Inline edits** (when forced). When the AWS provider only exposes a configuration as a nested block on the resource, we have to edit the starter resource directly. The first case is GAP-02: DynamoDB encryption is configured via the `server_side_encryption {}` block inside `aws_dynamodb_table`, and there is no sibling resource. We add the block in place, leave the original `# GAP-02:` starter comment as a hint to the grader, and document the change here.

**Why this is correct in practice.** Real GRC engineering teams don't get to choose the override pattern; AWS does. Insisting on a uniform style across all gaps would either duplicate resources unnecessarily (e.g., declaring a brand-new DynamoDB table just to keep the starter clean) or paper over the inline edit by hiding it in a `lifecycle` trick. Both are worse than just editing in place and being transparent about it.

**Trade-off accepted.** Inline edits make the diff against `upstream/main` slightly less obvious for the affected resources. Mitigated by retaining the original gap comment and adding a clear `# GAP-02 closure` block in the same resource.

## Gap closure log

| Gap | Layer 1 (Terraform) | Layer 2 (Rego) | Layer 4 (OSCAL) | Notes |
|---|---|---|---|---|
| GAP-01 (S3 SSE-KMS) | done | done | pending | `kms.tf` workload CMK; `hardening_uploads.tf` wires SSE-KMS; `hardening_iam.tf` grants Lambda least-priv key access. Policy `policies/s3_kms_required.rego` enforces, 4/4 tests pass. Verified live: `head-object` shows `ServerSideEncryption: aws:kms`, `SSEKMSKeyId` = workload CMK ARN. |
| GAP-02 (DynamoDB CMK) | done | done | pending | Inline `server_side_encryption` block added to `aws_dynamodb_table.intake` in `main.tf` (D-03 pattern). Reuses workload CMK from GAP-01 (D-01 single-workload-CMK). No new IAM needed: existing `aws_iam_role_policy.lambda_kms_workload` already grants `kms:Decrypt`/`GenerateDataKey` on the same key. Policy `policies/dynamodb_kms_required.rego` enforces, 4/4 tests pass. Verified live: `describe-table` shows `SSEType: KMS`, `KMSMasterKeyArn` = workload CMK ARN. |
| GAP-03 (S3 TLS-deny) | done | done | pending | `aws_s3_bucket_policy.uploads_tls_only` appended to `hardening_uploads.tf` (sibling-resource pattern). Statement: `Effect=Deny, Principal=*, Action=s3:*, Condition Bool aws:SecureTransport=false`. Policy `policies/s3_tls_required.rego` enforces, 4/4 tests pass (compliant case + 3 distinct misconfigurations: no policy, public-read, backwards condition). Verified live: identical authenticated HeadObject over HTTPS succeeds, over HTTP returns 403 Forbidden. |

(Table grows as gaps close.)

## Verification artifacts

End-to-end verification of GAP-01 (run on 2026-05-03 after apply):

```
$ aws s3api head-object --bucket acme-health-intake-uploads-3d0ff7d6 \
    --key uploads/a2844991-9eb4-4f31-abc0-103a2430fc16.bin
{
    "ServerSideEncryption": "aws:kms",
    "SSEKMSKeyId": "arn:aws:kms:us-east-1:871695561491:key/009f191c-9e8c-436e-8b77-909ea9b3119a",
    "BucketKeyEnabled": true,
    ...
}
```

End-to-end verification of GAP-02 (run on 2026-05-03 after apply):

```
$ aws dynamodb describe-table --table-name acme-health-intake-submissions-3d0ff7d6 \
    --query 'Table.SSEDescription'
{
    "Status": "ENABLED",
    "SSEType": "KMS",
    "KMSMasterKeyArn": "arn:aws:kms:us-east-1:871695561491:key/009f191c-9e8c-436e-8b77-909ea9b3119a"
}
```

In both cases the `SSEKMSKeyId` / `KMSMasterKeyArn` resolves to `aws_kms_key.app` (the workload CMK), proving that the Terraform-declared encryption configurations are enforced by AWS at the time of read/write, not just declared in code. The two resources share a single CMK by design (D-01 trust boundary). Both artifacts are candidates for inclusion in the signed evidence bundle once Layer 3 (signing pipeline) is built.

End-to-end verification of GAP-03 (run on 2026-05-03 after apply):

```
Test 1: aws s3api head-object ... --endpoint-url http://s3.us-east-1.amazonaws.com
  -> An error occurred (403) when calling the HeadObject operation: Forbidden

Test 2: aws s3api head-object ... --endpoint-url https://s3.us-east-1.amazonaws.com
  -> "ServerSideEncryption": "aws:kms"  (succeeds)
```

Same credentials, same bucket, same object, same operation. Only the transport differs. The 403 in Test 1 is the bucket policy's `aws:SecureTransport=false` deny statement firing. This is the controlled-comparison evidence that the TLS-deny is active and enforcing, not just present in the policy document. (An anonymous HTTP request also returns 403 but that test is ambiguous because S3's default public-access-block would already deny it; the authenticated comparison isolates the TLS condition.)

## What we didn't get to

(Filled in at submission.)
