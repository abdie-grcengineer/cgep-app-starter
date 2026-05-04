######################################################################
# Layer 3 prerequisite — GitHub OIDC + IAM role for the GRC pipeline.
#
# The pipeline does NOT use static AWS access keys. Instead it
# authenticates via OpenID Connect: GitHub's runner mints an OIDC
# JWT identifying the repo + workflow + branch + commit, and AWS
# trades it for short-lived STS credentials via the role declared
# below. The trust policy on that role is what limits which workflows
# can assume it.
#
# Two things to notice:
#   1. The OIDC provider is account-wide. If one already exists for
#      token.actions.githubusercontent.com, this resource will fail
#      and you should remove it from this file. (Single-account
#      sandbox: should not exist yet.)
#   2. The trust policy's `sub` condition pins the role to ONE
#      specific repo: abdie-grcengineer/cgep-app-starter. Any other
#      repo running through GitHub OIDC will fail to assume.
#
# HIPAA mapping: 164.312(d) Person or Entity Authentication
#                (no static credentials in CI; every assumption is
#                cryptographically tied to a specific workflow run)
######################################################################

# OIDC provider — already exists in this account (it's account-wide
# and shared across any IaC that wants to federate with GitHub).
# We reference it via a data source rather than declaring a resource
# we don't own. AWS validates the JWT signature against GitHub's
# published JWKS at
# https://token.actions.githubusercontent.com/.well-known/...
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

# The role the pipeline assumes.
resource "aws_iam_role" "gh_actions" {
  name = "${local.name_prefix}-gh-actions"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          # `sub` claim format documented at:
          # https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
          # Format: repo:<owner>/<repo>:<context>
          # StringLike with a wildcard so the role can be assumed by
          # both push and pull_request triggers (their sub strings
          # differ in the trailing context).
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:abdie-grcengineer/cgep-app-starter:*"
          }
        }
      },
    ]
  })

  tags = {
    Name    = "acme-health-gh-actions-role"
    Purpose = "grc-gate-pipeline"
  }
}

# Pipeline permissions.
#
# The pipeline runs `terraform plan + apply` over the entire stack,
# which means it transitively needs every action our terraform
# resources require: KMS create, IAM create, S3 create, DynamoDB
# create, CloudTrail create, Lambda create, etc. For the lab we
# attach AdministratorAccess to keep the demo focused on the GRC
# pattern rather than on IAM-scope-shaving.
#
# Production hardening (documented in WRITEUP.md as future work):
#   - Split into a plan-only role (read access) used by PRs, and
#     an apply role (write access) used only on push to main.
#   - Replace AdministratorAccess with a custom policy enumerating
#     just the actions terraform actually invokes.
#   - Add a permissions boundary so even if the role is
#     compromised, it cannot escalate beyond a fixed set.
#
# This is a deliberate, documented trade-off for the capstone
# scope, not an oversight.
resource "aws_iam_role_policy_attachment" "gh_actions_admin" {
  role       = aws_iam_role.gh_actions.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "gh_actions_role_arn" {
  value       = aws_iam_role.gh_actions.arn
  description = "Role ARN the GRC gate workflow assumes via OIDC."
}
