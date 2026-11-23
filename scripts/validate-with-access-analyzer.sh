#!/usr/bin/env bash
# Second opinion from AWS itself: run IAM Access Analyzer policy validation
# (ValidatePolicy, policy type SERVICE_CONTROL_POLICY) on every policy.
# Needs AWS credentials with access-analyzer:ValidatePolicy. The call only
# reads the policy text you send; it changes nothing in your account.
set -euo pipefail
cd "$(dirname "$0")/.."
failed=0
for f in policies/*.json; do
  findings=$(aws accessanalyzer validate-policy \
    --policy-type SERVICE_CONTROL_POLICY \
    --policy-document "file://$f" \
    --query 'findings[].[findingType,issueCode,findingDetails]' \
    --output text)
  if [ -z "$findings" ]; then
    echo "ok   $f"
  else
    echo "FIND $f"
    echo "$findings" | sed 's/^/     /'
    # ERROR and SECURITY_WARNING fail the run; WARNING and SUGGESTION are shown only.
    if echo "$findings" | grep -qE '^(ERROR|SECURITY_WARNING)'; then failed=1; fi
  fi
done
exit $failed
