# Acme Health Patient Intake API — CGE-P Capstone

This repository is a CGE-P capstone submission. It takes the [`cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter) workload (a deliberately under-governed telehealth Patient Intake API) and wraps it with the four GRC layers the brief calls for: a Terraform baseline, an OPA policy suite, a GitHub Actions GRC gate pipeline, and an OSCAL component-definition that ties the chain together. Primary framework is the **HIPAA Security Rule** (NIST SP 800-66 Rev. 2 cited as the OSCAL catalog).

The complete narrative, design decisions, and trade-offs live in [`WRITEUP.md`](WRITEUP.md).

## What this repo demonstrates

- **Five HIPAA gaps closed across all three layers** (Terraform fix + Rego policy + OSCAL implementation): GAP-01 (S3 SSE-KMS), GAP-02 (DynamoDB CMK), GAP-03 (S3 TLS-deny), GAP-04 (S3 versioning), GAP-07 (IAM least privilege). Three remaining gaps (GAP-05, GAP-06, GAP-08) are documented honestly as `implementation-status: planned` in OSCAL rather than falsely marked implemented.
- **5 OPA Rego policies, 26 unit tests, 100% pass.** Each policy is sub-packaged under `compliance.hipaa.*`, has a metadata block citing HIPAA control IDs and remediation, and detects both creates and in-place updates of non-compliant resources.
- **Layer 1 evidence vault** (`aws_s3_bucket.evidence`) with COMPLIANCE-mode Object Lock at 90-day default retention, SSE-KMS via a dedicated `aws_kms_key.evidence`, full public access block, and TLS-deny.
- **Multi-region CloudTrail with log-file validation**, KMS-encrypted under the evidence CMK, in a dedicated bucket.
- **GitHub Actions GRC gate pipeline** with five named steps (Plan, Policy check, Apply, Sign, Upload). Cosign keyless signing via GitHub OIDC. Every push to `main` produces a signed, SHA-256-recomputable, immutably-stored evidence bundle in the vault.
- **AWS Config detection layer** (`terraform/monitoring.tf`) with managed rules that continuously evaluate the live workload against the same controls our policies enforce at plan time.
- **Two PRs in repo history** prove the gate works as designed: PR #1 merged green, PR #4 was correctly blocked red because the Rego suite caught a re-introduced wildcard. (PR #2 + PR #3 are the bug-found / bug-fixed pair that uncovered and closed a create-only blind spot in the policy suite.)
- **OSCAL component-definition** at `oscal/component-definitions/acme-health-intake/component-definition.json` validates clean under `trestle validate -a`.

## Repository layout

```
.
|-- terraform/                       # Layer 1: Terraform baseline + hardening
|   |-- main.tf                      # the starter (resources marked GAP-NN)
|   |-- kms.tf                       # workload + evidence CMKs (D-01)
|   |-- evidence_vault.tf            # Object Lock COMPLIANCE/90 (D-05)
|   |-- cloudtrail.tf                # multi-region + LFV (D-06)
|   |-- tfstate.tf                   # remote state backend
|   |-- oidc.tf                      # GitHub OIDC role (D-07, D-08)
|   |-- monitoring.tf                # AWS Config managed rules
|   |-- hardening_uploads.tf         # GAP-01, 03, 04 closures
|   `-- hardening_iam.tf             # workload Lambda KMS access
|-- policies/                        # Layer 2: OPA/Rego suite
|   |-- s3_kms_required.rego         # GAP-01
|   |-- dynamodb_kms_required.rego   # GAP-02
|   |-- s3_tls_required.rego         # GAP-03
|   |-- s3_versioning_required.rego  # GAP-04
|   |-- iam_no_wildcards.rego        # GAP-07
|   `-- *_test.rego                  # 26 unit tests, +/- fixtures
|-- .github/workflows/
|   `-- grc-gate.yml                 # Layer 3: 5-step pipeline
|-- oscal/                           # Layer 4: machine-readable docs
|   |-- component-definitions/
|   |   `-- acme-health-intake/
|   |       `-- component-definition.json
|   `-- profiles/
|       `-- acme-health-hipaa/
|           `-- profile.json
|-- WRITEUP.md                       # Full narrative + design decisions
|-- README.md                        # This file
|-- LICENSE                          # MIT (inherited from starter)
|-- GAPS.md                          # Starter-defined gap list (untouched)
`-- FRAMEWORKS.md                    # Starter framework primer (untouched)
```

## How to run

### Prerequisites

- AWS account with Administrator-equivalent permissions (the demo provisions IAM, KMS, S3, DynamoDB, Lambda, API Gateway, CloudTrail, AWS Config)
- AWS CLI configured (`aws configure` or SSO)
- `terraform` >= 1.6
- `opa` (for running the Rego test suite)
- `cosign` (only needed for verification, not for deploy)

### Deploy

```bash
git clone https://github.com/abdie-grcengineer/cgep-app-starter
cd cgep-app-starter
make deploy AWS_PROFILE=<your-sandbox>
make test   AWS_PROFILE=<your-sandbox>
```

`make test` should return `{"submission_id": "...", "status": "received"}`. Once that succeeds the workload is up. The hardening overrides, evidence vault, CloudTrail, AWS Config, and pipeline-supporting resources are all part of the same `terraform apply`.

### Run the policy suite

```bash
opa test ./policies -v
```

Expect 26 PASS, 0 FAIL.

### Validate the OSCAL

```bash
pip3 install compliance-trestle
cd oscal
python3 -m trestle init --local   # idempotent if already initialized
python3 -m trestle validate -a
```

Expect both files VALID.

### Tear down

```bash
make destroy AWS_PROFILE=<your-sandbox>
```

Note: the evidence vault has Object Lock COMPLIANCE/90 set as the bucket default. Any objects uploaded by the pipeline cannot be deleted for 90 days, so the bucket will refuse to destroy until that retention expires. This is intentional per D-05; production HIPAA would extend the retention further.

## How a grader verifies a recent run

The brief's three required verifications: Cosign signature, SHA-256 recompute, Object Lock retention. All three hold on every signed bundle in the vault.

```bash
# 1. Find the latest signed bundle
BUCKET=$(cd terraform && terraform output -raw evidence_bucket)
LATEST=$(aws s3 ls s3://$BUCKET/runs/ | tail -1 | awk '{print $2}')
PREFIX="s3://$BUCKET/runs/${LATEST}"

# 2. Pull the three artifacts
aws s3 cp ${PREFIX}evidence-bundle.tar.gz       .
aws s3 cp ${PREFIX}evidence-bundle.sha256       .
aws s3 cp ${PREFIX}evidence-bundle.cosign.bundle .

# 3. Cosign signature against the public Sigstore log
cosign verify-blob \
  --bundle evidence-bundle.cosign.bundle \
  --certificate-identity-regexp \
    'https://github\.com/abdie-grcengineer/cgep-app-starter/\.github/workflows/grc-gate\.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  evidence-bundle.tar.gz

# 4. SHA-256 recompute
sha256sum -c evidence-bundle.sha256

# 5. Object Lock retention check (must be in the future for COMPLIANCE)
aws s3api head-object --bucket $BUCKET --key "runs/${LATEST}evidence-bundle.tar.gz" \
  --query '{Mode:ObjectLockMode, RetainUntil:ObjectLockRetainUntilDate}'
```

Expected results:
- Cosign: `Verified OK`
- SHA-256: `evidence-bundle.tar.gz: OK`
- Object Lock: `Mode=COMPLIANCE`, `RetainUntil` in the future

## Control-to-code mapping

The OSCAL component-definition is the canonical mapping. Every implemented requirement carries:

- `framework-control` prop with the canonical 164.x HIPAA citation
- `terraform-resource` props pointing at the Terraform addresses that satisfy the control
- `rego-policy` prop naming the deny rule that gates it
- `gap-closed` prop cross-referencing GAPS.md
- `links` rel=`evidence` pointing at signed bundles in the vault

The high-level mapping table also lives in [WRITEUP.md](WRITEUP.md) under "Gap closure log."

## Two PRs the brief requires

| # | URL | Purpose | Outcome |
|---|---|---|---|
| 1 | https://github.com/abdie-grcengineer/cgep-app-starter/pull/1 | Layer 1 + Layer 3 baseline | **Merged** (green) |
| 4 | https://github.com/abdie-grcengineer/cgep-app-starter/pull/4 | Re-introduces GAP-07 wildcard | **Closed unmerged** (gate fired red, blocked) |

PRs #2 and #3 are a bonus pair: #2 was a first attempt at the red demo that exposed a real bug (the Rego suite missed in-place updates); #3 fixed it with regression tests; #4 then correctly fired red on the same wildcard re-introduction.

## License

MIT, inherited from the starter. See [LICENSE](LICENSE).
