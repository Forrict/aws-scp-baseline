# AWS SCP baseline

Ten service control policies (SCPs) that we at [Forrict](https://www.forrict.com/en/) use as a starting point for an AWS Organization. Every policy is checked automatically on each push: JSON grammar, the SCP size limit, and every action and condition key against the official AWS Service Authorization Reference.

> Nederlandstalige uitleg: [README.nl.md](README.nl.md) en de blog [10 SCP's die elke AWS-organisatie nodig heeft](https://www.forrict.nl/nl/blog/).

**Test before you attach.** An SCP can block work in every account below the OU you attach it to. Attach these to a test OU first, check CloudTrail for `AccessDenied` errors, then roll out OU by OU. SCPs never apply to the management account.

## The policies

| # | File | What it blocks | Why |
| --- | --- | --- | --- |
| 1 | [`01-deny-leave-organization.json`](policies/01-deny-leave-organization.json) | `organizations:LeaveOrganization` | An account that leaves the organization also leaves every guardrail. |
| 2 | [`02-deny-root-user.json`](policies/02-deny-root-user.json) | All actions by the root user of member accounts, except privileged root tasks started centrally from the management account (`aws:AssumedRoot`) | Nobody should log in as root in day-to-day work. |
| 3 | [`03-restrict-regions.json`](policies/03-restrict-regions.json) | Regional actions outside `eu-central-1` and `eu-west-1`, plus enabling or disabling opt-in Regions | Keeps workloads and data in the EU Regions you chose. Global services are exempt. |
| 4 | [`04-protect-cloudtrail.json`](policies/04-protect-cloudtrail.json) | Stopping, deleting or changing CloudTrail trails | Attackers turn off logging first. |
| 5 | [`05-protect-guardduty.json`](policies/05-protect-guardduty.json) | Disabling GuardDuty, leaving the administrator account, and adding filters, IP lists or archive actions that could hide findings | Keeps threat detection on and its findings visible. |
| 6 | [`06-protect-config.json`](policies/06-protect-config.json) | Stopping or deleting the AWS Config recorder, delivery channel, rules and conformance packs | Config is the inventory and compliance history of your accounts. |
| 7 | [`07-protect-security-hub.json`](policies/07-protect-security-hub.json) | Disabling Security Hub or Security Hub CSPM, leaving the administrator account, disabling standards and deleting automation rules | Keeps the central security overview complete. |
| 8 | [`08-protect-access-analyzer.json`](policies/08-protect-access-analyzer.json) | Deleting IAM Access Analyzer analyzers and archiving its findings | Keeps unintended external access visible. |
| 9 | [`09-deny-iam-users-and-access-keys.json`](policies/09-deny-iam-users-and-access-keys.json) | Creating IAM users, access keys, console passwords and service-specific credentials | People sign in through IAM Identity Center; machines use roles. No long-lived keys. |
| 10 | [`10-protect-s3-block-public-access.json`](policies/10-protect-s3-block-public-access.json) | Changing the account-level S3 Block Public Access setting | Stops a bucket from being made public by turning the account setting off. |

## Before you use them

**Exception roles.** Policies 3 to 10 do not apply to two roles:

- `AWSControlTowerExecution`, the role AWS Control Tower uses to manage member accounts. If you don't use Control Tower, you can remove it.
- `GuardrailAdmin`, an example name for your own platform or security admin role. Replace it with the role you actually use, or create a role with this name. Without a matching role, only the management account can still make these changes.

The exception uses the `aws:PrincipalArn` condition key with `ArnNotLike`, so `arn:aws:iam::*:role/GuardrailAdmin` matches that role name in every account.

**Regions.** Policy 3 allows `eu-central-1` (Frankfurt) and `eu-west-1` (Ireland). Change the list in `aws:RequestedRegion` to the Regions you use. Do this before attaching: you lose access to resources in Regions you leave out. The exempt list of global services is taken from the AWS Control Tower Region deny control ([source](https://docs.aws.amazon.com/controltower/latest/controlreference/primary-region-deny-policy.html)). If you use Control Tower, use its built-in Region deny control instead of this policy.

**Control Tower.** Control Tower already protects the resources it sets up itself with [mandatory controls](https://docs.aws.amazon.com/controltower/latest/userguide/mandatory-controls.html). Policies 4 to 8 also cover the trails, recorders and security services that teams set up themselves. Keep `AWSControlTowerExecution` in the exception list or Control Tower updates will fail.

**Quotas.** You can attach at most 10 SCPs directly to the root, an OU or an account, and one SCP can be at most 10,240 characters ([source](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html)). Together with `FullAWSAccess` these ten policies need 11 slots, so combine some of them (for example 5 to 8) into one file before attaching them all to one target, or spread them over the root and your OUs.

**Deny list.** All statements are `Deny`. They only restrict; you still need `FullAWSAccess` (or your own allow policy) attached, and IAM policies to grant permissions.

## How the checks work

```bash
python3 scripts/validate.py          # all policies in policies/
python3 -m unittest discover -s tests -v
```

`scripts/validate.py` uses only the Python standard library and checks:

- valid JSON, no duplicate keys;
- SCP grammar: `Version` is `2012-10-17`; statements only use `Sid`, `Effect`, `Action`/`NotAction`, `Resource`/`NotResource` and `Condition`; no `Principal` ([source](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html));
- size: at most 10,240 characters, both as written and without whitespace;
- every action, including wildcards, exists in the [AWS Service Authorization Reference](https://servicereference.us-east-1.amazonaws.com/) (the machine-readable list AWS publishes);
- every condition operator is a valid IAM operator, and every condition key is a documented global key or a key of the service;
- no placeholders such as `[PRIVILEGED_ROLE]` are left.

The tests also run the validator against [deliberately broken policies](tests/fixtures/invalid/) (a typo in an action, a wrong condition key, a `Principal`, a policy that is too large, and more) and fail if any of them passes.

GitHub Actions runs these checks on every push and pull request, and weekly so we notice when AWS renames or removes an action.

**Second opinion from AWS.** `scripts/validate-with-access-analyzer.sh` sends each policy to IAM Access Analyzer `ValidatePolicy` with policy type `SERVICE_CONTROL_POLICY`. It needs AWS credentials that allow `access-analyzer:ValidatePolicy`, and changes nothing in your account. In CI this job runs only when the repository variable `AWS_VALIDATION_ROLE_ARN` is set.

## Sources and licence

Several policies are adapted from AWS's own [service-control-policy-examples](https://github.com/aws-samples/service-control-policy-examples) (MIT-0). This repository is also MIT-0: use it however you like, no attribution required. It comes without warranty; you are responsible for testing it in your own organization.

Questions, or help rolling this out? [Forrict landing zones](https://www.forrict.com/en/services/landingzones/).
