"""Enumeration of IAM principals (users + roles) and their policy documents.

v3 changes (closing the Deny/permission-boundary gap):
- Every Principal now also carries its permission boundary's statements
  (if one is attached), fetched the same way as any other managed policy.
- _action_matches() is effect-agnostic — it just answers "does this
  statement's Action/NotAction field match this action", independent of
  Allow/Deny. statement_grants() (Allow-only) and the new statement_denies()
  (Deny-only) both build on it, so there's one matching implementation
  instead of two that could drift apart.
- find_blocking_deny() scans identity policies (direct + group) AND the
  permission boundary for a Deny that would block a given action on a
  given resource, and reports whether that Deny is itself conditioned
  (i.e., we can't be certain it always applies).

Known limitation, stated plainly: a permission boundary's own Allow
statements aren't used to cap identity-policy grants (a full boundary
simulation would compute the intersection of boundary-allow and
identity-allow). Only the boundary's explicit Deny statements are
evaluated. A boundary that grants nothing beyond a narrow allow-list,
with no explicit Deny, will not be caught by find_blocking_deny() —
is_admin_equivalent() in checks/iam.py handles that specific case
separately by treating any non-wildcard boundary as disqualifying.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from plexavo.findings import Severity

# IAM errors that mean "this specific object can't be read right now",
# not "the scan is broken": the scanning principal genuinely lacks read
# access to one object (AccessDenied), or the object was deleted between
# the list call that named it and the per-object fetch (NoSuchEntity — a
# real race on any account that changes while a scan runs).
#
# Enumeration used to have no error handling at all, so either one took
# down the entire scan at stage 1, before a single check ran — the same
# class of bug as the S3 AccessDenied crash in storage.py (Hall of Bugs),
# which is also where the "skip the object, record it, keep scanning"
# shape used here comes from. Anything else still raises: an unexpected
# IAM error must not be quietly turned into "no findings."
_SKIPPABLE_IAM_ERROR_CODES = {"AccessDenied", "NoSuchEntity"}


def _is_skippable(exc: ClientError) -> bool:
    return exc.response.get("Error", {}).get("Code") in _SKIPPABLE_IAM_ERROR_CODES


def _note_skip(skipped: set | None, label: str, exc: ClientError) -> None:
    """Record that `label` could not be read, and why, so the caller can
    report it as unevaluated instead of silently under-reporting."""
    if skipped is not None:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        skipped.add(f"{label} ({code})")


@dataclass
class Principal:
    type: str          # "user" or "role"
    name: str
    arn: str
    # list of (policy_name, statements) — statements already normalized to
    # always be a list, and Action/Resource/Principal within them normalized too
    policies: list = field(default_factory=list)
    trust_policy: dict | None = None  # roles only
    # (policy_name, statements) for the permission boundary, or [] if none attached
    permission_boundary: list = field(default_factory=list)
    has_permission_boundary: bool = False


def _normalize(val):
    """AWS lets Action/Resource/Principal/NotAction/NotResource be a single
    string OR a list. Normalize to a list everywhere so check logic doesn't
    have to branch."""
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


def _fetch_managed_policy_statements(iam, policy_arn: str, skipped: set | None = None) -> list:
    try:
        version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )["PolicyVersion"]["Document"]
    except ClientError as e:
        if not _is_skippable(e):
            raise
        _note_skip(skipped, f"managed policy {policy_arn}", e)
        return []
    return _normalize(doc.get("Statement"))


def _policy_documents_for_user(iam, name: str, skipped: set | None = None) -> list:
    docs = []
    try:
        attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        inline_names = iam.list_user_policies(UserName=name)["PolicyNames"]
    except ClientError as e:
        if not _is_skippable(e):
            raise
        _note_skip(skipped, f"policies of user '{name}'", e)
        return docs
    for p in attached:
        docs.append((f"{p['PolicyName']} (direct)",
                     _fetch_managed_policy_statements(iam, p["PolicyArn"], skipped)))
    for name_ in inline_names:
        try:
            doc = iam.get_user_policy(UserName=name, PolicyName=name_)["PolicyDocument"]
        except ClientError as e:
            if not _is_skippable(e):
                raise
            _note_skip(skipped, f"inline policy '{name_}' on user '{name}'", e)
            continue
        docs.append((f"{name_} (direct inline)", _normalize(doc.get("Statement"))))
    return docs


def _policy_documents_for_group(iam, group_name: str, skipped: set | None = None) -> list:
    docs = []
    try:
        attached = iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
        inline_names = iam.list_group_policies(GroupName=group_name)["PolicyNames"]
    except ClientError as e:
        if not _is_skippable(e):
            raise
        _note_skip(skipped, f"policies of group '{group_name}'", e)
        return docs
    for p in attached:
        docs.append((f"{p['PolicyName']} (via group '{group_name}')",
                     _fetch_managed_policy_statements(iam, p["PolicyArn"], skipped)))
    for name_ in inline_names:
        try:
            doc = iam.get_group_policy(GroupName=group_name, PolicyName=name_)["PolicyDocument"]
        except ClientError as e:
            if not _is_skippable(e):
                raise
            _note_skip(skipped, f"inline policy '{name_}' on group '{group_name}'", e)
            continue
        docs.append((f"{name_} (inline via group '{group_name}')", _normalize(doc.get("Statement"))))
    return docs


def _policy_documents_for_role(iam, name: str, skipped: set | None = None) -> list:
    docs = []
    try:
        attached = iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
        inline_names = iam.list_role_policies(RoleName=name)["PolicyNames"]
    except ClientError as e:
        if not _is_skippable(e):
            raise
        _note_skip(skipped, f"policies of role '{name}'", e)
        return docs
    for p in attached:
        docs.append((f"{p['PolicyName']} (direct)",
                     _fetch_managed_policy_statements(iam, p["PolicyArn"], skipped)))
    for name_ in inline_names:
        try:
            doc = iam.get_role_policy(RoleName=name, PolicyName=name_)["PolicyDocument"]
        except ClientError as e:
            if not _is_skippable(e):
                raise
            _note_skip(skipped, f"inline policy '{name_}' on role '{name}'", e)
            continue
        docs.append((f"{name_} (direct inline)", _normalize(doc.get("Statement"))))
    return docs


def _permission_boundary(iam, boundary_field: dict | None, skipped: set | None = None) -> tuple[list, bool]:
    """boundary_field is the raw 'PermissionsBoundary' dict from list_users/
    list_roles, or None. Returns ([(name, statements)], has_boundary)."""
    if not boundary_field:
        return [], False
    arn = boundary_field.get("PermissionsBoundaryArn")
    if not arn:
        return [], False
    statements = _fetch_managed_policy_statements(iam, arn, skipped)
    return [(f"permission-boundary ({arn.split('/')[-1]})", statements)], True


def list_all_principals(session, skipped: set | None = None) -> list[Principal]:
    """Return every IAM user and role in the account with policies pre-loaded,
    including group-inherited policies and permission boundaries.

    A principal (or one policy document on it) the scanning identity can't
    read is kept with whatever did load, rather than aborting the scan, and
    a note naming it goes into `skipped` so the caller can report partial
    coverage. See _SKIPPABLE_IAM_ERROR_CODES for why, and for why anything
    other than AccessDenied/NoSuchEntity still raises.

    A principal that lands in `skipped` is genuinely under-evaluated: its
    unreadable policies produce no findings. That is reported, never
    presented as a clean result."""
    iam = session.client("iam")
    principals: list[Principal] = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page["Users"]:
            policies = _policy_documents_for_user(iam, u["UserName"], skipped)
            try:
                groups = iam.list_groups_for_user(UserName=u["UserName"])["Groups"]
            except ClientError as e:
                if not _is_skippable(e):
                    raise
                _note_skip(skipped, f"group memberships of user '{u['UserName']}'", e)
                groups = []
            for group in groups:
                policies += _policy_documents_for_group(iam, group["GroupName"], skipped)
            # PermissionsBoundary from list_users has proven unreliable —
            # fetch via get_user instead, the documented-reliable path.
            try:
                full_user = iam.get_user(UserName=u["UserName"])["User"]
            except ClientError as e:
                if not _is_skippable(e):
                    raise
                _note_skip(skipped, f"permission boundary of user '{u['UserName']}'", e)
                full_user = {}
            boundary_stmts, has_boundary = _permission_boundary(
                iam, full_user.get("PermissionsBoundary"), skipped)
            principals.append(Principal(
                type="user",
                name=u["UserName"],
                arn=u["Arn"],
                policies=policies,
                permission_boundary=boundary_stmts,
                has_permission_boundary=has_boundary,
            ))

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page["Roles"]:
            if "/aws-service-role/" in r["Arn"]:
                continue
            # Same fix: get_role instead of trusting list_roles for this field.
            try:
                full_role = iam.get_role(RoleName=r["RoleName"])["Role"]
            except ClientError as e:
                if not _is_skippable(e):
                    raise
                _note_skip(skipped, f"permission boundary of role '{r['RoleName']}'", e)
                full_role = {}
            boundary_stmts, has_boundary = _permission_boundary(
                iam, full_role.get("PermissionsBoundary"), skipped)
            principals.append(Principal(
                type="role",
                name=r["RoleName"],
                arn=r["Arn"],
                policies=_policy_documents_for_role(iam, r["RoleName"], skipped),
                trust_policy=r.get("AssumeRolePolicyDocument"),
                permission_boundary=boundary_stmts,
                has_permission_boundary=has_boundary,
            ))

    return principals


_ACTION_PATTERN_CACHE: dict[str, "re.Pattern[str]"] = {}


def _compile_action_pattern(pattern: str) -> "re.Pattern[str]":
    """Compile a single Action/NotAction entry into a regex. IAM supports
    exactly two wildcard characters here: '*' (any run of characters,
    including none) anywhere in the string, not just as a trailing
    "service:*", and '?' (exactly one character) - no other glob syntax
    (no bracket classes). Cached since the same policy statements get
    matched against many candidate actions across a scan."""
    cached = _ACTION_PATTERN_CACHE.get(pattern)
    if cached is not None:
        return cached
    regex_parts = []
    for ch in pattern:
        if ch == "*":
            regex_parts.append(".*")
        elif ch == "?":
            regex_parts.append(".")
        else:
            regex_parts.append(re.escape(ch))
    compiled = re.compile("^" + "".join(regex_parts) + "$")
    _ACTION_PATTERN_CACHE[pattern] = compiled
    return compiled


def _action_pattern_matches(pattern: str, action: str) -> bool:
    """Does this single Action/NotAction entry (already lowercased) match
    `action` (already lowercased)? Plain equality first as a fast path -
    only patterns that actually contain a wildcard character pay for
    regex compilation/matching."""
    if "*" not in pattern and "?" not in pattern:
        return pattern == action
    return _compile_action_pattern(pattern).match(action) is not None


def _action_matches(statement: dict, action: str) -> bool:
    """Does this statement's Action/NotAction field match `action`,
    independent of Effect? Shared by statement_grants (Allow) and
    statement_denies (Deny) so there's one matching implementation.

    Matches IAM's real wildcard semantics: '*' anywhere in an Action
    entry matches any run of characters, so "s3:Get*" correctly matches
    "s3:GetObject" - not just a literal "*" or an exact "service:*". The
    previous version only recognized a literal "*", an exact action, or
    a full "service:*" wildcard, so it silently missed every AWS-managed
    policy written with a prefix wildcard (e.g. every *ReadOnlyAccess-
    style managed policy uses "s3:Get*"/"s3:List*", not "s3:*") - those
    grants were invisible to everything built on this function:
    statement_grants/statement_denies, find_blocking_deny,
    action_within_boundary, has_full_wildcard_deny, and
    checks/iam.py's is_admin_equivalent, plus attack_paths.py's chain
    detection."""
    action = action.lower()
    if "NotAction" in statement and "Action" not in statement:
        excluded = _normalize(statement.get("NotAction"))
        return not any(_action_pattern_matches(a.lower(), action) for a in excluded)
    for a in _normalize(statement.get("Action")):
        if _action_pattern_matches(a.lower(), action):
            return True
    return False


def statement_grants(statement: dict, action_set: set[str]) -> set[str]:
    """Which actions from action_set this Allow statement grants."""
    if statement.get("Effect") != "Allow":
        return set()
    return {a for a in action_set if _action_matches(statement, a)}


def statement_denies(statement: dict, action_set: set[str]) -> set[str]:
    """Which actions from action_set this Deny statement blocks."""
    if statement.get("Effect") != "Deny":
        return set()
    return {a for a in action_set if _action_matches(statement, a)}


def statement_has_wildcard_action(statement: dict) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    if "Action" in statement:
        return "*" in _normalize(statement.get("Action"))
    if "NotAction" in statement:
        return True
    return False


def resource_is_wildcard(statement: dict) -> bool:
    """True if this statement's Resource is literally Resource:* (or it
    has a NotResource, an unbounded 'everything except X' grant). Deliberately
    narrow: a prefix-wildcard ARN like "arn:aws:s3:::bucket/*" is NOT treated
    as wildcard here - that's an extremely common, correctly-scoped pattern
    (object-level access to one bucket), not "grants against anything." Real
    prefix-wildcard ARN matching against a specific target lives in
    resource_includes() below."""
    if "Resource" in statement:
        return "*" in _normalize(statement.get("Resource"))
    if "NotResource" in statement:
        return True
    return False


def _resource_pattern_matches(pattern: str, arn: str) -> bool:
    """Does this single Resource/NotResource entry match `arn`? Same two
    AWS wildcard characters as Action ('*' any run of characters, '?'
    exactly one), reusing the same glob-to-regex compiler as
    _action_pattern_matches - but ARNs are case-sensitive (unlike action
    names), so this never lowercases either side."""
    if "*" not in pattern and "?" not in pattern:
        return pattern == arn
    return _compile_action_pattern(pattern).match(arn) is not None


def resource_includes(statement: dict, target_arn: str) -> bool:
    """Does this statement's Resource/NotResource field cover target_arn?

    Real IAM wildcard semantics via _resource_pattern_matches: '*' anywhere
    in a Resource entry matches any run of characters, so
    "arn:aws:iam::123456789012:role/*" correctly matches
    "arn:aws:iam::123456789012:role/AdminRole" - not just a literal "*" or
    an exact string. The previous version only recognized a literal "*" or
    exact ARN equality, so a plain prefix-wildcard resource (as ordinary as
    an sts:AssumeRole grant on "role/*") was invisible to
    find_blocking_deny/action_within_boundary and every checks/iam.py call
    site that checks a specific target ARN - Hall of Bugs, found by
    fusiontechstrategies."""
    if "NotResource" in statement and "Resource" not in statement:
        excluded = _normalize(statement.get("NotResource"))
        return not any(_resource_pattern_matches(r, target_arn) for r in excluded)
    resources = _normalize(statement.get("Resource"))
    return any(_resource_pattern_matches(r, target_arn) for r in resources)


def resource_grants_any_role(statement: dict) -> bool:
    """True if this statement's Resource field would let the principal
    assume ANY IAM role in the account, now or in the future - a bare "*"
    (resource_is_wildcard), or an ARN pattern whose role-name segment is
    itself a bare wildcard (e.g. "arn:aws:iam::123456789012:role/*").
    Deliberately narrower than a general prefix-wildcard match:
    "role/Admin*" only reaches roles named Admin*, not every role, and
    must NOT be treated the same as "role/*" - that distinction is exactly
    what IAM-06 ("can assume ANY role") needs and IAM-05 (a specific named
    target) does not. Used only for sts:AssumeRole's Resource field -
    scoped to role ARNs on purpose."""
    if resource_is_wildcard(statement):
        return True
    return any(r.endswith("role/*") for r in _normalize(statement.get("Resource")))


def resource_grants_any_policy(statement: dict) -> bool:
    """The managed-policy counterpart of resource_grants_any_role: does this
    statement's Resource field cover EVERY managed policy in the account,
    now or in the future — a bare "*", or an ARN pattern whose policy-name
    segment is itself a bare wildcard (e.g.
    "arn:aws:iam::123456789012:policy/*")?

    Same deliberate narrowness: "policy/Billing*" only reaches policies
    named Billing*, so it is NOT "any policy" and must go through the
    per-policy path instead. Used by IAM-03, whose previous version
    recognized only a literal "*" here and so silently missed the
    ordinary "policy/*" form — the same prefix-wildcard blind spot
    already fixed for sts:AssumeRole's Resource field."""
    if resource_is_wildcard(statement):
        return True
    return any(r.endswith("policy/*") for r in _normalize(statement.get("Resource")))


def action_within_boundary(principal: Principal, action: str, resource_arn: str | None) -> bool:
    """True if this principal has no permission boundary, OR the boundary's
    Allow statements actually permit `action` on `resource_arn` (Resource:*
    scope if resource_arn is None). A boundary that doesn't explicitly
    allow an action implicitly denies it — that's how permission boundaries
    work: effective access is the intersection of identity policy and
    boundary, not the identity policy alone."""
    if not principal.has_permission_boundary:
        return True
    for _name, statements in principal.permission_boundary:
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            if not _action_matches(stmt, action):
                continue
            if resource_arn is not None and resource_includes(stmt, resource_arn):
                return True
            if resource_arn is None and resource_is_wildcard(stmt):
                return True
    return False


def find_blocking_deny(principal: Principal, action: str, resource_arn: str | None = None) -> tuple[bool, bool]:
    """Scan identity policies (direct + group, already merged into
    principal.policies) AND the permission boundary for a Deny statement
    that matches `action` on a resource scope covering resource_arn (or
    Resource:* if resource_arn is None).

    Returns (found_matching_deny, deny_is_conditioned). If the Deny itself
    has a Condition block, we can't be certain it always applies — callers
    should downgrade rather than fully suppress in that case.
    """
    all_sources = list(principal.policies) + list(principal.permission_boundary)
    for _name, statements in all_sources:
        for stmt in statements:
            if stmt.get("Effect") != "Deny":
                continue
            if not _action_matches(stmt, action):
                continue
            if resource_arn is not None and not resource_includes(stmt, resource_arn):
                continue
            if resource_arn is None and not resource_is_wildcard(stmt):
                continue
            return True, bool(stmt.get("Condition"))
    return False, False


def _condition_adjustment(stmt: dict) -> tuple[Severity, str, str]:
    """A Condition block on the grant statement itself means we can't
    safely claim it's unconditional. Downgrade Critical -> High and say so
    via confidence/evidence — never as free text baked into raw_detail, so
    the report can show "this needs a human look" as a distinct,
    structured fact instead of a sentence buried in prose. Returns
    (severity, confidence, evidence).

    Moved here from checks/iam.py (unchanged behavior) so checks/storage.py
    can reuse it too — Hall of Bugs, found by fusiontechstrategies: STOR-20
    fired at full Critical/Confirmed on a Principal:* bucket policy even
    when a Condition (e.g. aws:PrincipalOrgID) genuinely restricted it,
    exactly the uncertainty this function already exists to handle for
    every IAM check. A generic statement-level helper with no IAM-specific
    coupling, so it belongs in this module alongside the other shared
    policy-statement evaluators, not duplicated per check module."""
    condition = stmt.get("Condition")
    if condition:
        keys = ", ".join(condition.keys())
        return (
            Severity.HIGH,
            "Likely — see note",
            f"Grant is scoped by a Condition block ({keys}) — not evaluated automatically; "
            f"whether it meaningfully restricts access needs a manual look.",
        )
    return Severity.CRITICAL, "Confirmed", ""


def has_full_wildcard_deny(principal: Principal) -> bool:
    """True if a Deny statement grants Action:*/Resource:* (or NotAction/
    NotResource equivalent) — a full deny-all. Deliberately narrow: this
    only catches the unambiguous full-deny case, not partial per-service
    denies, which would require real policy simulation to resolve safely."""
    all_sources = list(principal.policies) + list(principal.permission_boundary)
    for _name, statements in all_sources:
        for stmt in statements:
            if stmt.get("Effect") != "Deny":
                continue
            action_is_wildcard = (
                ("Action" in stmt and "*" in _normalize(stmt.get("Action")))
                or ("NotAction" in stmt and "Action" not in stmt)
            )
            if action_is_wildcard and resource_is_wildcard(stmt):
                return True
    return False
