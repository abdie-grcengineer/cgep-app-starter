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

## Gap closure log

| Gap | Layer 1 (Terraform) | Layer 2 (Rego) | Layer 4 (OSCAL) | Notes |
|---|---|---|---|---|
| GAP-01 (S3 SSE-KMS) | done | done | pending | `kms.tf` workload CMK; `hardening_uploads.tf` wires SSE-KMS; `hardening_iam.tf` grants Lambda least-priv key access. Policy `policies/s3_kms_required.rego` enforces, 4/4 tests pass. Verified live: `head-object` shows `ServerSideEncryption: aws:kms`, `SSEKMSKeyId` = workload CMK ARN. |

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

The `SSEKMSKeyId` ARN is `aws_kms_key.app` (workload CMK), proving that the Terraform-declared encryption configuration is enforced by AWS at the time of object PUT, not just declared. This artifact is a candidate for inclusion in the signed evidence bundle once Layer 3 (signing pipeline) is built.

## What we didn't get to

(Filled in at submission.)
