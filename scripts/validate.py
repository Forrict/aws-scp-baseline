#!/usr/bin/env python3
"""Validate service control policies (SCPs) without AWS credentials.

Checks every JSON file passed on the command line (default: policies/*.json):

* the file is valid JSON without duplicate keys;
* the document follows the SCP grammar from the AWS Organizations user guide
  (Version, Statement, Sid, Effect, Action/NotAction, Resource/NotResource,
  Condition; no Principal or NotPrincipal);
* the policy fits the SCP size quota (10,240 characters), both as written and
  with whitespace removed;
* every action (including wildcards) exists in the AWS Service Authorization
  Reference, which AWS publishes as JSON at
  https://servicereference.us-east-1.amazonaws.com/;
* every condition operator is a valid IAM operator and every condition key is
  either a documented global key or a key of the service in the reference;
* no unfilled placeholders such as [PRIVILEGED_ROLE] or ${Account} remain.

Exit code 0 means every policy passed. Uses the Python standard library only.
"""
from __future__ import annotations

import fnmatch
import glob
import json
import os
import re
import sys
import time
import urllib.request

REFERENCE_INDEX = "https://servicereference.us-east-1.amazonaws.com/"
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".cache", "service-reference")
CACHE_MAX_AGE = 24 * 3600

# Quota: "Service control policies: 10,240 characters"
# https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html
MAX_SCP_CHARS = 10240

TOP_LEVEL_KEYS = {"Version", "Id", "Statement"}
STATEMENT_KEYS = {"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition"}
FORBIDDEN_STATEMENT_KEYS = {"Principal", "NotPrincipal"}

# IAM condition operators
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
BASE_OPERATORS = {
    "StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
    "StringLike", "StringNotLike",
    "NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals",
    "NumericGreaterThan", "NumericGreaterThanEquals",
    "DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals",
    "DateGreaterThan", "DateGreaterThanEquals",
    "Bool", "BinaryEquals", "IpAddress", "NotIpAddress",
    "ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike",
}

# Global condition keys used or likely to be used in SCPs.
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
GLOBAL_KEYS = {
    "aws:PrincipalArn", "aws:PrincipalAccount", "aws:PrincipalOrgID", "aws:PrincipalOrgPaths",
    "aws:PrincipalIsAWSService", "aws:PrincipalServiceName", "aws:PrincipalServiceNamesList",
    "aws:PrincipalType", "aws:userid", "aws:username", "aws:AssumedRoot", "aws:SourceIdentity",
    "aws:FederatedProvider", "aws:TokenIssueTime", "aws:MultiFactorAuthPresent",
    "aws:MultiFactorAuthAge", "aws:ViaAWSService", "aws:CalledVia", "aws:CalledViaFirst",
    "aws:CalledViaLast", "aws:SourceIp", "aws:SourceVpc", "aws:SourceVpce", "aws:VpcSourceIp",
    "aws:RequestedRegion", "aws:SecureTransport", "aws:CurrentTime", "aws:EpochTime",
    "aws:TagKeys", "aws:ResourceAccount", "aws:ResourceOrgID", "aws:ResourceOrgPaths",
    "aws:SourceAccount", "aws:SourceArn", "aws:SourceOrgID", "aws:SourceOrgPaths",
    "aws:Ec2InstanceSourceVpc", "aws:Ec2InstanceSourcePrivateIPv4", "aws:SourceVpcArn",
}
GLOBAL_KEY_PREFIXES = ("aws:PrincipalTag/", "aws:RequestTag/", "aws:ResourceTag/")

PLACEHOLDER = re.compile(r"\[[A-Z_]+\]|\$\{(Account|Region|Partition)\}")


class DuplicateKeyError(ValueError):
    pass


def _no_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise DuplicateKeyError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def _fetch_json(url: str, cache_name: str):
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, cache_name)
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < CACHE_MAX_AGE:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    req = urllib.request.Request(url, headers={"User-Agent": "scp-validator"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.load(resp)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return data


class ServiceReference:
    def __init__(self):
        index = _fetch_json(REFERENCE_INDEX, "index.json")
        self.urls = {entry["service"].lower(): entry["url"] for entry in index}
        self._services = {}

    def service(self, prefix: str):
        prefix = prefix.lower()
        if prefix not in self.urls:
            return None
        if prefix not in self._services:
            self._services[prefix] = _fetch_json(self.urls[prefix], f"{prefix}.json")
        return self._services[prefix]

    def actions(self, prefix: str):
        svc = self.service(prefix)
        return [] if svc is None else [a["Name"] for a in svc.get("Actions", [])]

    def condition_keys(self, prefix: str):
        svc = self.service(prefix)
        return [] if svc is None else [k["Name"] for k in svc.get("ConditionKeys", [])]


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _valid_operator(op: str) -> bool:
    for prefix in ("ForAllValues:", "ForAnyValue:"):
        if op.startswith(prefix):
            op = op[len(prefix):]
    if op == "Null":
        return True
    if op.endswith("IfExists"):
        op = op[: -len("IfExists")]
    return op in BASE_OPERATORS


def _key_matches(key: str, pattern: str) -> bool:
    # Reference keys use ${TagKey}-style variables, e.g. "aws:RequestTag/${TagKey}".
    regex = "^" + re.escape(pattern).replace(re.escape("${"), "${") + "$"
    regex = re.sub(r"\$\{[^}]+\}", ".+", regex)
    return re.match(regex, key, re.IGNORECASE) is not None


def check_policy(path: str, ref: ServiceReference) -> list[str]:
    errors: list[str] = []
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    try:
        doc = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (json.JSONDecodeError, DuplicateKeyError) as exc:
        return [f"invalid JSON: {exc}"]

    if PLACEHOLDER.search(raw):
        errors.append("contains an unfilled placeholder such as [PRIVILEGED_ROLE] or ${Account}")

    minified = json.dumps(doc, separators=(",", ":"))
    if len(minified) > MAX_SCP_CHARS:
        errors.append(f"too large: {len(minified)} characters without whitespace (max {MAX_SCP_CHARS})")
    if len(raw) > MAX_SCP_CHARS:
        errors.append(f"too large as written: {len(raw)} characters (max {MAX_SCP_CHARS}); "
                      "the CLI and SDKs store whitespace as-is")

    if not isinstance(doc, dict):
        return errors + ["policy must be a JSON object"]
    for key in doc:
        if key not in TOP_LEVEL_KEYS:
            errors.append(f"unknown top-level element {key!r}")
    if doc.get("Version") != "2012-10-17":
        errors.append('Version must be "2012-10-17"')
    statements = doc.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        return errors + ["Statement must be a non-empty array"]

    sids = set()
    for i, st in enumerate(statements):
        where = f"Statement[{i}]"
        if not isinstance(st, dict):
            errors.append(f"{where}: must be an object")
            continue
        for key in st:
            if key in FORBIDDEN_STATEMENT_KEYS:
                errors.append(f"{where}: {key} is not supported in SCPs")
            elif key not in STATEMENT_KEYS:
                errors.append(f"{where}: unknown element {key!r}")
        sid = st.get("Sid")
        if sid is not None:
            if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9]+", sid):
                errors.append(f"{where}: Sid must be alphanumeric")
            elif sid in sids:
                errors.append(f"{where}: duplicate Sid {sid!r}")
            sids.add(sid)
        if st.get("Effect") not in ("Allow", "Deny"):
            errors.append(f"{where}: Effect must be Allow or Deny")
        if ("Action" in st) == ("NotAction" in st):
            errors.append(f"{where}: needs exactly one of Action or NotAction")
        if ("Resource" in st) == ("NotResource" in st):
            errors.append(f"{where}: needs exactly one of Resource or NotResource")

        for element in ("Action", "NotAction"):
            for action in _as_list(st.get(element, [])):
                errors.extend(f"{where}.{element}: {msg}" for msg in _check_action(action, ref))

        for element in ("Resource", "NotResource"):
            for res in _as_list(st.get(element, [])):
                if not isinstance(res, str) or not (res == "*" or res.startswith("arn:")):
                    errors.append(f"{where}.{element}: {res!r} is not '*' or an ARN")

        cond = st.get("Condition", {})
        if not isinstance(cond, dict):
            errors.append(f"{where}.Condition: must be an object")
            continue
        services = {a.split(":", 1)[0].lower() for a in _as_list(st.get("Action", []) or st.get("NotAction", []))
                    if isinstance(a, str) and ":" in a}
        for op, block in cond.items():
            if not _valid_operator(op):
                errors.append(f"{where}.Condition: unknown operator {op!r}")
            if not isinstance(block, dict):
                errors.append(f"{where}.Condition.{op}: must be an object")
                continue
            for key, value in block.items():
                if not _known_condition_key(key, services, ref):
                    errors.append(f"{where}.Condition.{op}: unknown condition key {key!r}")
                for v in _as_list(value):
                    if not isinstance(v, (str, bool, int)):
                        errors.append(f"{where}.Condition.{op}.{key}: invalid value {v!r}")
                if op.startswith("Arn"):
                    for v in _as_list(value):
                        if isinstance(v, str) and not v.startswith("arn:"):
                            errors.append(f"{where}.Condition.{op}.{key}: {v!r} is not an ARN")
                if op == "Null":
                    for v in _as_list(value):
                        if v not in ("true", "false", True, False):
                            errors.append(f"{where}.Condition.Null.{key}: value must be true or false")
    return errors


def _check_action(action, ref: ServiceReference) -> list[str]:
    if not isinstance(action, str):
        return [f"{action!r} is not a string"]
    if action == "*":
        return []
    if ":" not in action:
        return [f"{action!r} must look like service:Action"]
    prefix, name = action.split(":", 1)
    if ref.service(prefix) is None:
        return [f"unknown service prefix {prefix!r} in {action!r}"]
    names = ref.actions(prefix)
    if not any(fnmatch.fnmatchcase(n.lower(), name.lower()) for n in names):
        return [f"{action!r} matches no action of service {prefix!r}"]
    return []


def _known_condition_key(key: str, services: set[str], ref: ServiceReference) -> bool:
    if key in GLOBAL_KEYS or key.startswith(GLOBAL_KEY_PREFIXES):
        return True
    prefix = key.split(":", 1)[0].lower()
    if prefix in services or prefix in ref.urls:
        return any(_key_matches(key, pattern) for pattern in ref.condition_keys(prefix))
    return False


def main(argv: list[str]) -> int:
    paths = argv[1:] or sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "policies", "*.json")))
    if not paths:
        print("no policies found")
        return 1
    ref = ServiceReference()
    failed = 0
    for path in paths:
        errors = check_policy(path, ref)
        name = os.path.relpath(path)
        if errors:
            failed += 1
            print(f"FAIL {name}")
            for err in errors:
                print(f"     - {err}")
        else:
            with open(path, encoding="utf-8") as fh:
                size = len(json.dumps(json.load(fh), separators=(",", ":")))
            print(f"ok   {name} ({size} characters)")
    print(f"\n{len(paths) - failed} of {len(paths)} policies passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
