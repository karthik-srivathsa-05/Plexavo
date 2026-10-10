"""Offline tests for explainer.py. No real API calls anywhere in this
file — the "API path" tests use a fake Anthropic-shaped client.

Run: python test_explainer_offline.py
"""

import re
import sys
from plexavo.findings import Finding, Severity
from plexavo.report.ai_narration import (
    explain_finding,
    _parse_sections,
    _short_name,
    _strip_stray_markdown_headers,
    _strip_leading_markdown_noise,
    COMMON_CHECK_TEMPLATES,
)

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def f(check_id, resource_arn="arn:aws:iam::111111111111:role/test-role", raw_detail="x", account_context="x",
      confidence="Confirmed", evidence=""):
    return Finding(check_id=check_id, title="x", severity=Severity.CRITICAL,
                   resource_arn=resource_arn, raw_detail=raw_detail, account_context=account_context,
                   confidence=confidence, evidence=evidence)


class ExplodingClient:
    """A fake Anthropic client that raises if ANY method is touched —
    proves the templated path genuinely never reaches the network,
    not just that it happens not to in this test run."""
    class messages:
        @staticmethod
        def create(**kwargs):
            raise AssertionError("Templated finding should NEVER call the API — this client should never be invoked")


class FakeResponse:
    def __init__(self, text=None, blocks=None, stop_reason="end_turn"):
        self.stop_reason = stop_reason
        if blocks is not None:
            self.content = blocks
        else:
            self.content = [type("Block", (), {"text": text, "type": "text"})()]


class FakeClient:
    def __init__(self, response_text=None, raise_exc=None, response_blocks=None, stop_reason="end_turn"):
        self._text = response_text
        self._raise = raise_exc
        self._blocks = response_blocks
        self._stop_reason = stop_reason
        self.messages = self

    def create(self, **kwargs):
        if self._raise:
            raise self._raise
        if self._blocks is not None:
            return FakeResponse(blocks=self._blocks, stop_reason=self._stop_reason)
        return FakeResponse(text=self._text, stop_reason=self._stop_reason)


print("=== _short_name ===")
assert_true(_short_name("arn:aws:iam::111111111111:role/my-role") == "my-role", "Extracts name after last /")
assert_true(_short_name("arn:aws:s3:::my-bucket") == "my-bucket", "Extracts name after last : when no /")
assert_true(_short_name("i-0abc123") == "i-0abc123", "Bare ID with no separators returned as-is")

print("\n=== Every template produces non-empty impact/next_step, with ZERO API contact ===")
for check_id in COMMON_CHECK_TEMPLATES:
    finding = f(check_id)
    result = explain_finding(finding, client=ExplodingClient())
    assert_true(result.source == "template", f"{check_id} routes to template (got source={result.source})")
    assert_true(bool(result.impact.strip()), f"{check_id} impact is non-empty")
    assert_true(bool(result.how_to_fix.strip()), f"{check_id} how_to_fix is non-empty")
    assert_true(bool(result.next_step.strip()), f"{check_id} next_step is non-empty — this is new, every template must set it")
EXPECTED_TEMPLATE_IDS = {
    "IAM-01", "IAM-06", "IAM-09", "IAM-10", "IAM-11", "IAM-13",
    "NET-01", "NET-02", "STOR-19", "ENC-29", "LOG-25", "EC2-32",
}
assert_true(set(COMMON_CHECK_TEMPLATES) == EXPECTED_TEMPLATE_IDS,
            f"Templated check ids are exactly the expected set (got {sorted(COMMON_CHECK_TEMPLATES)})")

print("\n=== LOG-25 (GuardDuty): account-level finding, template does not depend on a resource name ===")
# LOG-25's real finding has resource_arn="account" — no per-resource
# identifier to substitute, unlike bucket/volume/user templates. The
# template must still produce complete, correct guidance.
finding = f("LOG-25", resource_arn="account", raw_detail="GuardDuty is not enabled in this region.")
result = explain_finding(finding, client=ExplodingClient())
assert_true(result.source == "template", f"LOG-25 routes to template (got source={result.source})")
assert_true("guardduty create-detector" in result.how_to_fix, "LOG-25 fix names the actual enable command")
assert_true("guardduty create-detector" in result.next_step, "LOG-25 next_step names the actual enable command")
assert_true("<PLACEHOLDER" not in result.how_to_fix and "<PLACEHOLDER" not in result.next_step,
            "LOG-25 has no per-resource value to fill, so no placeholder should appear")

print("\n=== EC2-32 (IMDSv2): instance id and region come from the Finding, no placeholders ===")
EC2_ID = "i-0abc1234def567890"
EC2_CMD = "modify-instance-metadata-options"
finding = f("EC2-32", resource_arn=EC2_ID, account_context="iam_role_attached=True, region=ap-south-1")
result = explain_finding(finding, client=ExplodingClient())
assert_true(result.source == "template", f"EC2-32 routes to template with zero API contact (got source={result.source})")
for label, text in (("next_step", result.next_step), ("how_to_fix", result.how_to_fix)):
    assert_true(EC2_ID in text, f"EC2-32 {label} contains the real instance id")
    assert_true(EC2_CMD in text, f"EC2-32 {label} names modify-instance-metadata-options")
    assert_true("--http-tokens required" in text, f"EC2-32 {label} sets --http-tokens required")
    assert_true("--region ap-south-1" in text, f"EC2-32 {label} carries the region from account_context")
assert_true(result.next_step.count("aws ec2 ") == 1, "EC2-32 next_step holds exactly one command")
ec2_cmd_line = result.next_step.split(": ", 1)[1]
assert_true(ec2_cmd_line in result.how_to_fix,
            "EC2-32 next_step command is character-for-character the command in how_to_fix")
assert_true(f"Instance '{EC2_ID}'" in result.impact, "EC2-32 impact names the real instance id")

print("\n=== EC2-32: no region in account_context -> --region omitted entirely, no placeholder ===")
finding = f("EC2-32", resource_arn=EC2_ID, account_context="iam_role_attached=True")
result = explain_finding(finding, client=ExplodingClient())
assert_true("--region" not in result.next_step, "EC2-32 next_step has no --region when the region is unknown")
assert_true("--region" not in result.how_to_fix, "EC2-32 how_to_fix has no --region when the region is unknown")
assert_true(EC2_ID in result.next_step and "--http-tokens required" in result.next_step,
            "EC2-32 without a region still produces the full command")
assert_true(result.next_step.split(": ", 1)[1] in result.how_to_fix,
            "EC2-32 next_step command still matches how_to_fix without a region")

print("\n=== EC2-32: no unfilled placeholders in any field, in any account_context variant ===")
for ctx in ("iam_role_attached=True, region=ap-south-1", "iam_role_attached=False", "x", ""):
    finding = f("EC2-32", resource_arn=EC2_ID, account_context=ctx)
    result = explain_finding(finding, client=ExplodingClient())
    for label, text in (("impact", result.impact), ("next_step", result.next_step), ("how_to_fix", result.how_to_fix)):
        # Match the placeholder token shape (<PLACEHOLDER-X>, <INSTANCE_ID>, <region>) rather than any
        # bare "<" or ">", so legitimate comparison text could never false-fail this check.
        assert_true(re.search(r"<[A-Za-z][A-Za-z0-9_-]*>", text) is None
                    and "<PLACEHOLDER" not in text and "<INSTANCE" not in text,
                    f"EC2-32 {label} has no unfilled placeholder (account_context={ctx!r})")

print("\n=== EC2-32: role sentence follows iam_role_attached, falls back to generic text when absent ===")
with_role = explain_finding(
    f("EC2-32", resource_arn=EC2_ID, account_context="iam_role_attached=True, region=ap-south-1"),
    client=ExplodingClient())
no_role = explain_finding(
    f("EC2-32", resource_arn=EC2_ID, account_context="iam_role_attached=False, region=ap-south-1"),
    client=ExplodingClient())
missing_key = explain_finding(f("EC2-32", resource_arn=EC2_ID, account_context="x"), client=ExplodingClient())
assert_true("credentials" in with_role.impact and "security-credentials" in with_role.impact,
            "Role-attached impact explains the credential theft path")
assert_true("Capital One" in with_role.impact, "Role-attached impact names the Capital One precedent")
assert_true("Capital One" not in no_role.impact, "No-role impact does not claim the Capital One chain")
assert_true("No IAM role is attached" in no_role.impact and "user-data" in no_role.impact,
            "No-role impact states no role is attached and names the remaining exposure")
assert_true("Capital One" not in missing_key.impact and "IAM role" not in missing_key.impact,
            "Missing iam_role_attached key -> generic text, no role sentence either way")
assert_true(missing_key.impact.startswith(f"Instance '{EC2_ID}' still accepts IMDSv1"),
            "Generic impact still carries the base paragraph")
assert_true(with_role.impact.startswith(missing_key.impact) and no_role.impact.startswith(missing_key.impact),
            "Both role variants extend the same base paragraph")
assert_true(with_role.next_step == no_role.next_step and with_role.how_to_fix == no_role.how_to_fix,
            "Role attachment changes only the impact text, not the fix command or fix detail")
assert_true(missing_key.next_step == with_role.next_step.replace(" --region ap-south-1", ""),
            "Missing role key and missing region only change the optional pieces, not the base command")

print("\n=== EC2-32: full fix detail covers the real-world gotchas and avoids absolute claims ===")
result = explain_finding(
    f("EC2-32", resource_arn=EC2_ID, account_context="iam_role_attached=True, region=ap-south-1"),
    client=ExplodingClient())
for needle in ("MetadataNoToken", "AWS/EC2", "--http-put-response-hop-limit 2", "Terraform", "CloudFormation",
               "http_tokens = \"required\"", "without a reboot", "--http-tokens optional"):
    assert_true(needle in result.how_to_fix, f"EC2-32 how_to_fix mentions {needle!r}")
all_ec2_text = " ".join((with_role.impact, no_role.impact, missing_key.impact,
                         result.next_step, result.how_to_fix)).lower()
for banned in ("no legitimate reason", "always", "never"):
    assert_true(banned not in all_ec2_text, f"EC2-32 text avoids the absolute claim {banned!r}")
assert_true("\u2014" not in all_ec2_text, "EC2-32 text contains no em dashes")

print("\n=== Confidence/evidence are copied from the Finding, not decided by the template ===")
finding = f("IAM-01", confidence="Likely — see note", evidence="Grant is scoped by a Condition block (aws:SourceIp)")
result = explain_finding(finding, client=ExplodingClient())
assert_true(result.confidence == "Likely — see note", "Template path passes through the Finding's confidence unchanged")
assert_true(result.evidence == "Grant is scoped by a Condition block (aws:SourceIp)", "Template path passes through the Finding's evidence unchanged")
# And the default case, so the passthrough isn't just tested at the non-default value:
finding = f("IAM-01")
result = explain_finding(finding, client=ExplodingClient())
assert_true(result.confidence == "Confirmed", "Default confidence passes through unchanged too")

print("\n=== Templated checks correctly substitute the actual resource name, not a placeholder ===")
finding = f("IAM-01", resource_arn="arn:aws:iam::111111111111:user/lab-admin")
result = explain_finding(finding, client=ExplodingClient())
assert_true("lab-admin" in result.impact, "The real resource name appears in the templated text")

print("\n=== use_ai=False (default): non-templated check returns None, zero network ===")
finding = f("IAM-05")  # NOT in COMMON_CHECK_TEMPLATES
result = explain_finding(finding, client=ExplodingClient())  # use_ai=False is the default
assert_true(result is None, f"No template + AI off -> None, no API call attempted (got {result!r})")

print("\n=== use_ai=True bypasses the template entirely, even for a templated check_id ===")
fake_response_for_iam01 = (
    "IMPACT: This policy grants unrestricted access to every resource.\n\n"
    "HOW TO FIX: Replace the wildcard with least-privilege actions.\n\n"
    "NEXT STEP: Detach the policy immediately."
)
finding = f("IAM-01")  # IS in COMMON_CHECK_TEMPLATES
result = explain_finding(finding, client=FakeClient(response_text=fake_response_for_iam01), use_ai=True)
assert_true(result.source == "api", f"use_ai=True routes a templated check to the API, not the template (got source={result.source})")
assert_true("unrestricted access to every resource" in result.impact, "The AI response is used verbatim, not the template's fixed text")

print("\n=== _parse_sections: well-formatted plain output ===")
raw = ("IMPACT: The bucket is public. Calls s3:GetObject to read everything.\n\n"
       "HOW TO FIX: Run aws s3api put-public-access-block ...\n\n"
       "NEXT STEP: Run the command above now.")
impact, how_to_fix, next_step = _parse_sections(raw)
assert_true(impact == "The bucket is public. Calls s3:GetObject to read everything.", f"impact parsed correctly (got: {impact!r})")
assert_true(how_to_fix.startswith("Run aws s3api"), f"how_to_fix parsed correctly (got: {how_to_fix!r})")
assert_true(next_step == "Run the command above now.", f"next_step parsed correctly (got: {next_step!r})")

print("\n=== _parse_sections: markdown bold headers, no colon ===")
raw = ("**IMPACT** The role is over-permissioned.\n\n"
       "**HOW TO FIX** Scope the trust policy.\n\n"
       "**NEXT STEP** Edit the trust policy now.")
impact, how_to_fix, next_step = _parse_sections(raw)
assert_true(impact == "The role is over-permissioned.", f"Handles markdown bold + missing colon (got: {impact!r})")
assert_true(how_to_fix == "Scope the trust policy.", "how_to_fix parsed with bold headers")
assert_true(next_step == "Edit the trust policy now.", "next_step parsed with bold headers")

print("\n=== _parse_sections: lowercase headers ===")
raw = "impact: x\n\nhow to fix: y\n\nnext step: z"
impact, how_to_fix, next_step = _parse_sections(raw)
assert_true((impact, how_to_fix, next_step) == ("x", "y", "z"), f"Case-insensitive matching works (got: {(impact, how_to_fix, next_step)!r})")

print("\n=== _parse_sections: headers not found at all -> raw text preserved, not dropped ===")
raw = "Something went generically wrong with no structure."
impact, how_to_fix, next_step = _parse_sections(raw)
assert_true(impact == raw and how_to_fix == "" and next_step == "", "Unparseable text goes entirely into impact, nothing silently lost")

print("\n=== API path: non-templated check_id, well-formatted fake response ===")
fake_response_text = (
    "IMPACT: This role can assume an admin role. Calls sts:AssumeRole on the target role.\n\n"
    "HOW TO FIX: Scope the Resource field to specific roles.\n\n"
    "NEXT STEP: Edit the policy's Resource field now."
)
finding = f("IAM-05")  # NOT in COMMON_CHECK_TEMPLATES — must go through the API path
result = explain_finding(finding, client=FakeClient(response_text=fake_response_text), use_ai=True)
assert_true(result.source == "api", f"Non-templated check routes to the API path (got source={result.source})")
assert_true(result.impact == "This role can assume an admin role. Calls sts:AssumeRole on the target role.", "API response parsed correctly end-to-end")
assert_true(result.next_step == "Edit the policy's Resource field now.", "next_step parsed correctly from the API response")

print("\n=== REGRESSION: ThinkingBlock before TextBlock — the exact bug hit in production ===")
# Simulates Sonnet 5's real default behavior: a ThinkingBlock (no .text
# attribute at all, matching the real SDK type) appears at content[0],
# with the actual answer in a TextBlock afterward. This exact shape
# crashed the original content[0].text code with:
# "'ThinkingBlock' object has no attribute 'text'"
thinking_block = type("ThinkingBlock", (), {"type": "thinking", "thinking": ""})()
text_block = type("TextBlock", (), {
    "type": "text",
    "text": "IMPACT: x\n\nHOW TO FIX: y\n\nNEXT STEP: z",
})()
finding = f("IAM-05")
result = explain_finding(finding, client=FakeClient(response_blocks=[thinking_block, text_block]), use_ai=True)
assert_true(result.source == "api", f"Correctly extracts text past a leading ThinkingBlock (got source={result.source})")
assert_true(result.impact == "x", f"Text content correctly parsed despite the thinking block (got: {result.impact!r})")

print("\n=== REGRESSION: '##' markdown headings immediately before the label ===")
raw = "## IMPACT: x\n\n## HOW TO FIX: y\n\n## NEXT STEP: z"
impact, how_to_fix, next_step = _parse_sections(raw)
assert_true((impact, how_to_fix, next_step) == ("x", "y", "z"), f"'##' prefix directly on the header is stripped cleanly (got: {(impact, how_to_fix, next_step)!r})")

print("\n=== REGRESSION: exact production bug — orphaned bare '##' line inside section content ===")
# Matches what was actually observed: a bare '##' line with blank lines
# on both sides, sitting inside what should be clean prose content.
raw = ("IMPACT: The role can escalate to admin.\n\n"
       "##\n\n"
       "An attacker assumes the role directly.\n\n"
       "HOW TO FIX: Remove the assume-role permission.\n\n"
       "##\n\n"
       "NEXT STEP: Remove the permission now.")
impact, how_to_fix, next_step = _parse_sections(raw)
assert_true("##" not in impact and "##" not in how_to_fix, f"No orphaned '##' fragments leak into parsed content (got impact={impact!r}, how_to_fix={how_to_fix!r})")

print("\n=== _strip_stray_markdown_headers: unit test in isolation ===")
assert_true(_strip_stray_markdown_headers("real content\n\n##\n\nmore content") == "real content\n\nmore content",
            "Bare '##' line removed, surrounding content and spacing preserved")
assert_true(_strip_stray_markdown_headers("### also stripped\nreal line") == "### also stripped\nreal line",
            "A line with real text after the markers is correctly left alone — that's the split regex's job, not this cleanup's")

print("\n=== REGRESSION: exact production bug — colon-BEFORE-asterisks ordering ===")
# Matches what was actually observed this round: 'IMPACT: **' —
# opposite order from the earlier '**IMPACT:' case already tested.
raw = ("IMPACT: ** The role can escalate to admin.\n\n"
       "HOW TO FIX: ** Remove the assume-role permission.\n\n"
       "NEXT STEP: ** Remove it now.")
impact, how_to_fix, next_step = _parse_sections(raw)
assert_true(impact == "The role can escalate to admin.", f"Colon-before-asterisks noise stripped cleanly (got: {impact!r})")
assert_true("**" not in impact and "**" not in how_to_fix and "**" not in next_step, "No stray ** survives in any section")

print("\n=== _strip_leading_markdown_noise: unit test, several real orderings in one pass ===")
assert_true(_strip_leading_markdown_noise(": ** real content") == "real content", "colon-then-asterisks")
assert_true(_strip_leading_markdown_noise("** : real content") == "real content", "asterisks-then-colon")
assert_true(_strip_leading_markdown_noise("## real content") == "real content", "hash-then-space")
assert_true(_strip_leading_markdown_noise("real content") == "real content", "no noise — content untouched")
assert_true(_strip_leading_markdown_noise("plain text with ** bold ** later") == "plain text with ** bold ** later",
            "Only LEADING noise is touched — intentional formatting deeper in the text survives untouched")

print("\n=== REGRESSION: truncated response (stop_reason=max_tokens) is flagged, not silently returned ===")
truncated_text = "IMPACT: x\n\nHOW TO FIX: Step 1: do this\naws iam delete-role-policy \\\n  --role-name"
finding = f("IAM-05")
result = explain_finding(finding, client=FakeClient(response_text=truncated_text, stop_reason="max_tokens"), use_ai=True)
assert_true("TRUNCATED" in result.how_to_fix, f"Truncation is visibly flagged, not silently returned as if complete (got: {result.how_to_fix!r})")

print("\n=== FALSE POSITIVE GUARD: normal, complete response does NOT get flagged as truncated ===")
finding = f("IAM-05")
result = explain_finding(finding, client=FakeClient(response_text=fake_response_text, stop_reason="end_turn"), use_ai=True)
assert_true("TRUNCATED" not in result.how_to_fix, "A normal, complete response is not falsely flagged")

print("\n=== API path: exception during the call -> graceful fallback, not a crash ===")
finding = f("IAM-05", raw_detail="original technical detail here", confidence="Likely — see note", evidence="some evidence")
result = explain_finding(finding, client=FakeClient(raise_exc=ConnectionError("simulated network failure")), use_ai=True)
assert_true(result.source == "fallback", f"A failed API call falls back gracefully (got source={result.source})")
assert_true(result.impact == "original technical detail here", "Fallback preserves the original raw_detail, doesn't lose the finding")
# Per the OSS plan's §3.3 contract: the fallback must be silent in the
# report — no raw exception text ever reaches report-facing content.
# how_to_fix/next_step are empty specifically so html_report.py's
# `explained` check (bool(how_to_fix) and bool(next_step)) routes this
# through the same clean single-paragraph render as "no explanation was
# ever attempted," not a layout with a Python exception message sitting
# in HOW TO FIX.
assert_true(result.how_to_fix == "", "Fallback never leaks the raw exception into report-facing content")
assert_true(result.next_step == "", "Fallback leaves next_step empty too — no partial/misleading content")
# Confidence/evidence are Finding-level facts, set by detection logic —
# they must survive a failed API call unchanged, not reset to defaults,
# since they have nothing to do with whether the AI call succeeded.
assert_true(result.confidence == "Likely — see note", "Fallback still carries through the Finding's actual confidence, not a default")
assert_true(result.evidence == "some evidence", "Fallback still carries through the Finding's actual evidence, not a default")

print("\n=== API path: missing anthropic package (not installed) also falls back cleanly ===")
# `anthropic` is an optional extra — a user who never installed it and
# hits a non-templated finding must get the exact same clean fallback
# as any other API failure, not an ImportError crashing the scan.
import builtins as _builtins
_real_import = _builtins.__import__


def _blocked_import(name, *args, **kwargs):
    if name == "anthropic":
        raise ImportError("simulated: anthropic not installed")
    return _real_import(name, *args, **kwargs)


_builtins.__import__ = _blocked_import
try:
    finding = f("IAM-05", raw_detail="original technical detail here")
    result = explain_finding(finding, use_ai=True)
finally:
    _builtins.__import__ = _real_import
assert_true(result.source == "fallback", f"Missing anthropic package falls back, doesn't crash (got source={result.source})")
assert_true(result.how_to_fix == "", "Missing-package fallback is just as silent as any other failure")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
