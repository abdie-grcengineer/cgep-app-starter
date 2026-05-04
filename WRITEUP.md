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

### D-08: Pipeline IAM role uses AdministratorAccess for the lab; production would scope tightly

The GitHub Actions role (`acme-health-intake-gh-actions`) has the AWS-managed `AdministratorAccess` policy attached. We made this trade-off deliberately: getting the GRC gate pattern (plan → policy → apply → sign → upload) running end-to-end is the centerpiece of the capstone, and shaving `terraform apply` permissions to exactly the actions Terraform invokes is a multi-day exercise that would not change the gate's behavior.

**What production would do differently.**

1. **Split the role.** A read-only role for PRs (plan + state read) and an apply role for push-to-main (plan + apply + state write). The apply role's trust policy would condition on `ref:refs/heads/main` so PR runs cannot escalate.
2. **Replace AdministratorAccess** with a curated allow-list enumerating only the `s3:*`, `kms:*`, `iam:*`, etc., that this Terraform stack genuinely needs.
3. **Add a permissions boundary** so the apply role cannot create a new role or policy outside the boundary.
4. **Limit the trust-policy `sub` further** from `repo:abdie-grcengineer/cgep-app-starter:*` to `repo:.../environment:prod` or per-branch, depending on environment model.

The capstone does NOT do these because the demo value is the gate firing, not the IAM-shaving. Documented rather than hand-waved.

### D-07: GitHub OIDC trust pinned to one repo, wildcard on context

The pipeline role's trust policy uses `StringLike` on the OIDC `sub` claim with the value `repo:abdie-grcengineer/cgep-app-starter:*`. The wildcard at the end deliberately allows ANY context (push branch, pull_request, environment) under THIS specific repo to assume the role.

**Why one repo with a context wildcard.** GitHub's OIDC `sub` claim format is `repo:<owner>/<repo>:<context>` where `<context>` differs across event types (push from a branch, pull_request from a fork, environment-scoped runs). Pinning the repo while leaving the context open is the smallest scope that still allows the GRC gate workflow to run on both PRs (gate-only) and pushes-to-main (full sequence). A different repo, even with the same workflow file, cannot impersonate this one.

**Trade-off accepted.** A workflow file that gets deleted from this repo and added to a forked branch (a malicious-fork-PR scenario) could trigger this role, since `pull_request` events run against the head ref. The mitigations in production would be (a) require approval before workflow runs from forks, configurable in GitHub repo settings; (b) scope the workflow to the upstream `pull_request_target` event with explicit branch restrictions. Documented as future work.

### D-06: CloudTrail logs are encrypted with the evidence CMK, not a third dedicated key

CloudTrail's log files are encrypted at rest under `aws_kms_key.evidence`, the same CMK that protects the pipeline-signed bundles. We deliberately did not create a third CloudTrail-dedicated CMK.

**Why.** Both artifact classes share a trust boundary: they are both audit-tier records of what happened in the system, both are read by the same auditor/grader audience, and neither is touched by the workload Lambda. Adding a third CMK would create an additional key policy to maintain and a third surface to monitor for rotation, with no change in the actual security posture. The evidence CMK's policy was extended to grant `cloudtrail.amazonaws.com` `kms:GenerateDataKey*` and `kms:Decrypt`, scoped via the `kms:EncryptionContext:aws:cloudtrail:arn` condition to ONLY trails inside this account. A confused-deputy attempt by a CloudTrail trail in a different account would fail.

**Trade-off accepted.** A future requirement to retire the evidence CMK (e.g., compliance-driven rotation policy) would mean migrating BOTH evidence bundles AND CloudTrail to a successor key. With separate keys we could rotate one without the other. We accept this as a low-probability future cost in exchange for present-day operational simplicity.

**Why CloudTrail's bucket has no Object Lock.** The brief requires Object Lock only on the evidence vault. CloudTrail provides its own integrity mechanism via log file validation: every hour the service writes a digest file containing SHA-256 hashes of the log files plus a digital signature over the chain. Object Lock on top would add tamper-resistance, but nothing in our threat model is improved by stacking the two: a tamper attempt is already detected by a hash recomputation, and an attacker who can defeat LFV (i.e., can rewrite the signed digest in S3) is sophisticated enough that bucket-level immutability does not move the needle. Documented choice rather than oversight.

### D-05: Evidence vault uses COMPLIANCE-mode Object Lock with 90-day default retention

The evidence vault (`aws_s3_bucket.evidence`) ships with `aws_s3_bucket_object_lock_configuration.evidence` set to `mode = "COMPLIANCE"` and `days = 90`.

**Why COMPLIANCE over GOVERNANCE.** GOVERNANCE allows IAM principals with `s3:BypassGovernanceRetention` to override retention in emergencies; COMPLIANCE allows no override at all, not even by the account root. For an audit chain of custody, the property auditors care about is "this artifact has not been tampered with since it was uploaded." GOVERNANCE creates a backdoor (the IAM grant that lets someone bypass), and an auditor's natural next question is "who has that grant, and how do you detect a misuse." COMPLIANCE removes the question entirely. The cost is operational: there is no escape hatch even for legitimate emergencies. We accept that cost as the right one for a HIPAA-aligned vault.

**Why 90 days, not longer or shorter.** The grading criterion in the brief is "Object Lock retention check" on a recent run. The retention must still be active when the grader looks. 90 days clears that bar with margin (the project window is 30 days), demonstrates a meaningful immutability window, and avoids the operational cost of locking the sandbox bucket for years while we iterate. Production HIPAA-grade record keeping for PHI would extend this to the 6-year floor; this is a deliberate scoped-down choice for the lab, with the production target documented here so the rationale is clear.

**Trade-off accepted.** Once an object lands in this bucket, it cannot be deleted for 90 days even if it was uploaded in error (e.g., an accidental commit). The pipeline (Layer 3) must not upload artifacts containing secrets or other content we'd want to remove. Validation upstream of the upload step is therefore part of the design, not an optional check.

### D-04: Least-privilege actions derived from real handler code, not anticipated future use

The starter's wildcards (`dynamodb:*`, `s3:*`) were replaced with the exact actions `handler.py` performs today: `dynamodb:PutItem` and `s3:PutObject`. We deliberately did NOT pre-grant `dynamodb:GetItem` or `s3:GetObject` "in case we add reads later." HIPAA 164.312(a)(1) requires minimum-necessary access, and "we might need this someday" is the failure mode that produces wildcards in the first place.

**Trade-off accepted.** When the workload genuinely needs new actions (a query API, a download endpoint), the IAM policy must be updated in the same PR as the handler change. This forces a security review every time the data-access surface widens, which is what the control is for. The cost is a slightly noisier change history; the benefit is that no IAM grant exists without a code path to justify it.

### D-03: Hardening pattern depends on what the AWS provider exposes

The capstone aims to keep the starter file (`terraform/main.tf`) recognizable so a grader can diff against the upstream and see exactly what we added. We follow that rule where the AWS provider lets us, and break it where it doesn't.

- **Sibling-resource overrides** (preferred). When AWS exposes a configuration as its own Terraform resource, we add it as a sibling in a new file. Examples: `aws_s3_bucket_server_side_encryption_configuration` for GAP-01, `aws_s3_bucket_versioning` for GAP-04 (later), `aws_s3_bucket_policy` for GAP-03 (later). Starter file untouched.
- **Inline edits** (when forced). When the AWS provider only exposes a configuration as a nested block on the resource, we have to edit the starter resource directly. The first case is GAP-02: DynamoDB encryption is configured via the `server_side_encryption {}` block inside `aws_dynamodb_table`, and there is no sibling resource. We add the block in place, leave the original `# GAP-02:` starter comment as a hint to the grader, and document the change here.

**Why this is correct in practice.** Real GRC engineering teams don't get to choose the override pattern; AWS does. Insisting on a uniform style across all gaps would either duplicate resources unnecessarily (e.g., declaring a brand-new DynamoDB table just to keep the starter clean) or paper over the inline edit by hiding it in a `lifecycle` trick. Both are worse than just editing in place and being transparent about it.

**Trade-off accepted.** Inline edits make the diff against `upstream/main` slightly less obvious for the affected resources. Mitigated by retaining the original gap comment and adding a clear `# GAP-02 closure` block in the same resource.

## Layer 1 deliverables status

The brief's required Layer 1 components, in order of completion:

| Deliverable | Status | Notes |
|---|---|---|
| Customer-managed KMS keys with rotation | done | Two keys per D-01: `aws_kms_key.app` (workload PHI), `aws_kms_key.evidence` (audit) |
| Hardening overrides for ≥5 starter gaps | done | 5 gaps closed across L1+L2 (GAP-01, 02, 03, 04, 07) |
| S3 evidence bucket with Object Lock | done | `aws_s3_bucket.evidence` with COMPLIANCE/90 (D-05), versioning, SSE-KMS via evidence CMK, TLS-deny, full BPA |
| CloudTrail (multi-region, log-file-validation) | done | `aws_cloudtrail.main`: multi-region, LFV enabled, KMS-encrypted with evidence CMK (D-06). Dedicated trail bucket with the same hardening pattern as the evidence vault, minus Object Lock (LFV provides integrity already). |

**Layer 1 complete.** All four required components shipped, all hardening overrides for ≥5 starter gaps in place, all opa policies passing, primary framework declared and traceable.

## Layer 3 progress

The GRC gate workflow lives at [.github/workflows/grc-gate.yml](.github/workflows/grc-gate.yml). Five named steps in order:

1. **Plan** — `terraform init + plan + show -json` to produce `tfplan.json`
2. **Policy check** — Conftest evaluates every package in `./policies` against the plan JSON. Pipefail propagates conftest's exit code through the `tee | jq` pipeline so a deny rule actually fails the step. Both human-readable and JSON outputs captured.
3. **Apply** — gated by `if: github.event_name == 'push' && github.ref == 'refs/heads/main'`. PR runs never reach this step.
4. **Sign** — Cosign keyless signing using GitHub OIDC. The runner exchanges its workflow JWT for a Sigstore Fulcio-issued ephemeral X.509 certificate naming this exact workflow path and commit, signs the bundle blob, and writes a Rekor transparency-log entry. The `--bundle` artifact contains the cert + signature + Rekor inclusion proof for offline verification.
5. **Upload** — bundle, SHA-256, and Cosign bundle written to the evidence vault under `runs/<utc-timestamp>-<commit-prefix>/`. Object Lock COMPLIANCE/90 retention applies automatically by bucket default.

Pipeline supporting infra:

| Component | File | Purpose |
|---|---|---|
| Terraform S3 backend | `terraform/tfstate.tf` | versioned, KMS-encrypted (evidence CMK), DynamoDB-locked |
| GitHub OIDC role | `terraform/oidc.tf` | `acme-health-intake-gh-actions`, trust policy pinned to `repo:abdie-grcengineer/cgep-app-starter:*` (D-07) |
| Evidence CMK grant | `terraform/kms.tf` | role gets `kms:GenerateDataKey*` + `Decrypt` for bundle encryption |

Two PRs gated by the workflow remain to be pushed to satisfy the brief's "two PRs in repo history" requirement: one green (passes the gate, merges, evidence bundle produced), one red (intentionally re-introduces a closed gap, gate fires, PR blocked). Those will be added once the workflow is verified end-to-end via the first push.

Verification command for graders:

```
cosign verify-blob \
  --bundle evidence-bundle.cosign.bundle \
  --certificate-identity-regexp \
    'https://github\.com/abdie-grcengineer/cgep-app-starter/\.github/workflows/grc-gate\.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  evidence-bundle.tar.gz
```

## Gap closure log

| Gap | Layer 1 (Terraform) | Layer 2 (Rego) | Layer 4 (OSCAL) | Notes |
|---|---|---|---|---|
| GAP-01 (S3 SSE-KMS) | done | done | pending | `kms.tf` workload CMK; `hardening_uploads.tf` wires SSE-KMS; `hardening_iam.tf` grants Lambda least-priv key access. Policy `policies/s3_kms_required.rego` enforces, 4/4 tests pass. Verified live: `head-object` shows `ServerSideEncryption: aws:kms`, `SSEKMSKeyId` = workload CMK ARN. |
| GAP-02 (DynamoDB CMK) | done | done | pending | Inline `server_side_encryption` block added to `aws_dynamodb_table.intake` in `main.tf` (D-03 pattern). Reuses workload CMK from GAP-01 (D-01 single-workload-CMK). No new IAM needed: existing `aws_iam_role_policy.lambda_kms_workload` already grants `kms:Decrypt`/`GenerateDataKey` on the same key. Policy `policies/dynamodb_kms_required.rego` enforces, 4/4 tests pass. Verified live: `describe-table` shows `SSEType: KMS`, `KMSMasterKeyArn` = workload CMK ARN. |
| GAP-03 (S3 TLS-deny) | done | done | pending | `aws_s3_bucket_policy.uploads_tls_only` appended to `hardening_uploads.tf` (sibling-resource pattern). Statement: `Effect=Deny, Principal=*, Action=s3:*, Condition Bool aws:SecureTransport=false`. Policy `policies/s3_tls_required.rego` enforces, 4/4 tests pass (compliant case + 3 distinct misconfigurations: no policy, public-read, backwards condition). Verified live: identical authenticated HeadObject over HTTPS succeeds, over HTTP returns 403 Forbidden. |
| GAP-04 (S3 versioning) | done | done | pending | `aws_s3_bucket_versioning.uploads` appended to `hardening_uploads.tf` with `status = "Enabled"`. Policy `policies/s3_versioning_required.rego` enforces, 3/3 tests pass (compliant case + 2 misconfigurations: no resource, status=Suspended). No lifecycle rule for noncurrent-version expiry: defeats recovery intent and would need its own design decision. Verified live: `aws s3api get-bucket-versioning` returns `Status: Enabled`. |
| GAP-07 (IAM wildcards) | done | done | pending | Inline edit on `main.tf` (D-03 pattern; the wildcards live inside the starter's `aws_iam_role_policy.lambda_inline`, can't be overridden from a sibling file). `dynamodb:*` -> `["dynamodb:PutItem"]`. `s3:*` -> `["s3:PutObject"]` (and resource scoped to `bucket/*`, dropping the bucket-level ARN since PutObject only acts on objects). Derived from handler.py: it does only `put_item` and `put_object`. Policy `policies/iam_no_wildcards.rego` (sub-package `compliance.hipaa.iam`) enforces, 6/6 tests pass (compliant + service-wildcard + super-admin + mixed-list + Deny-wildcard-allowed + aws_iam_policy resource type). Verified live: API call with attachment succeeds, `dynamodb:PutItem` and `s3:PutObject` both work, object lands SSE-KMS-encrypted. |

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

Evidence vault verification (run on 2026-05-03 after apply):

```
$ aws s3api get-object-lock-configuration --bucket acme-health-intake-evidence-3d0ff7d6
{
    "ObjectLockConfiguration": {
        "ObjectLockEnabled": "Enabled",
        "Rule": {
            "DefaultRetention": { "Mode": "COMPLIANCE", "Days": 90 }
        }
    }
}

$ aws s3api get-bucket-encryption --bucket acme-health-intake-evidence-3d0ff7d6
{
    "...SSEAlgorithm": "aws:kms",
    "...KMSMasterKeyID": "arn:aws:kms:us-east-1:871695561491:key/2bb5dbe4-..."  (evidence CMK)
}

$ aws s3api get-bucket-versioning --bucket acme-health-intake-evidence-3d0ff7d6
{ "Status": "Enabled", "MFADelete": "Disabled" }

$ aws s3api get-public-access-block --bucket acme-health-intake-evidence-3d0ff7d6
{ "BlockPublicAcls": true, "IgnorePublicAcls": true,
  "BlockPublicPolicy": true, "RestrictPublicBuckets": true }

$ aws s3 ls s3://acme-health-intake-evidence-3d0ff7d6/ --endpoint-url http://s3...
  -> AccessDenied: "explicit deny in a resource-based policy"
```

Five properties confirmed: Object Lock enabled in COMPLIANCE mode with 90-day default retention; encryption with the evidence CMK (distinct from the workload CMK, per D-01); versioning enabled (required by Object Lock); public access fully blocked; TLS-only traffic enforced. The evidence CMK ARN ends in `2bb5dbe4-...`, different from the workload CMK ARN (`009f191c-...`), demonstrating the trust-boundary separation declared in D-01.

CloudTrail verification (run on 2026-05-03 after apply):

```
$ aws cloudtrail describe-trails --trail-name-list <trail-arn>
{
    "Name": "acme-health-intake-3d0ff7d6",
    "IsMultiRegion": true,
    "LogFileValidation": true,
    "KMSKeyId": "arn:aws:kms:us-east-1:871695561491:key/2bb5dbe4-...",  (evidence CMK)
    "Bucket": "acme-health-intake-cloudtrail-3d0ff7d6"
}

$ aws cloudtrail get-trail-status --name <trail-arn>
{ "IsLogging": true, "LatestDeliveryError": null }
```

Three properties critical for HIPAA 164.312(b) Audit Controls and 164.312(c)(1) Integrity confirmed: multi-region coverage (so future expansions do not silently log nothing), log file validation (cryptographic tamper-evidence via SHA-256 digest chains), and KMS encryption under our evidence CMK (D-06). The trail's bucket is dedicated per the brief and hardened with the same pattern as the evidence vault (versioning, SSE-KMS, BPA, TLS-deny), minus Object Lock which would be redundant with LFV.

## What we didn't get to

(Filled in at submission.)
