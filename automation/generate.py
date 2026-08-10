"""Turn normalized threats into drafted KQL detections using the Claude API.

Each threat becomes zero or more proposed detections, mapped to a MITRE ATT&CK
tactic that matches one of the repo's tactic folders. Output is behavioral where
possible (durable) rather than raw IOCs (which go stale in days).

Auth: uses the standard Anthropic credential chain (ANTHROPIC_API_KEY, or an
`ant auth login` profile). If no credentials are available the module returns an
empty list so the rest of the pipeline (ingest + validate) can still be exercised.
"""
from __future__ import annotations

import json
import sys

import anthropic

# Structured-output schema: forces valid, parseable JSON back from the model.
_DETECTION_SCHEMA = {
    "type": "object",
    "properties": {
        "detections": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tactic": {"type": "string"},
                    "technique": {"type": "string"},
                    "severity": {"type": "string", "enum": ["Low", "Medium", "High", "Critical"]},
                    "title": {"type": "string"},
                    "purpose": {"type": "string"},
                    "kql": {"type": "string"},
                    "tuning_notes": {"type": "string"},
                },
                "required": ["tactic", "technique", "severity", "title", "purpose", "kql", "tuning_notes"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["detections"],
    "additionalProperties": False,
}

_SYSTEM = """You are a senior detection engineer writing Kusto Query Language (KQL) \
detections for Microsoft Defender XDR / Advanced Hunting.

Given a newly-exploited vulnerability or threat, propose behavioral hunting \
detections that would surface exploitation or post-exploitation activity on \
endpoints. Rules:
- Prefer durable BEHAVIORAL detections (process lineage, command-line patterns, \
suspicious file/registry/network activity) over raw IOCs (specific IPs/hashes), \
which go stale within days.
- Use only real Advanced Hunting tables: DeviceProcessEvents, DeviceNetworkEvents, \
DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, \
DeviceEvents, EmailEvents, IdentityLogonEvents, etc.
- Every query must start from a table, use `| where Timestamp > ago(1d)`, and end \
with a `| project` of the useful investigative columns.
- Map each detection to the single best-fitting MITRE ATT&CK tactic from the \
allowed list provided by the user.
- Include an ATT&CK technique ID (e.g. T1059.001) where applicable.
- If a threat does not lend itself to a sound endpoint detection, return no \
detection for it rather than a low-quality guess.
- Keep each query focused; tune-able allowlists belong in tuning_notes, not hardcoded."""


def _build_prompt(threats: list[dict], allowed_tactics: list[str]) -> str:
    lines = [
        "Allowed tactics (use exactly these strings for the `tactic` field):",
        ", ".join(allowed_tactics),
        "",
        "Newly exploited threats from the last few days:",
        "",
    ]
    for t in threats:
        lines.append(
            f"- {t['id']} — {t['title']}\n"
            f"    vendor/product: {t.get('vendor','')} / {t.get('product','')}\n"
            f"    description: {t.get('description','')}\n"
            f"    required action: {t.get('required_action','')}\n"
            f"    known ransomware use: {t.get('known_ransomware','Unknown')}"
        )
    lines.append("")
    lines.append(
        "Propose behavioral KQL detections for the threats where a sound endpoint "
        "detection is possible. Return them in the structured `detections` array."
    )
    return "\n".join(lines)


def generate(threats: list[dict], config: dict) -> list[dict]:
    if not threats:
        return []

    allowed = list(config.get("tactic_dirs", {}).keys())
    model = config.get("model", "claude-opus-5")

    try:
        client = anthropic.Anthropic()
    except Exception:  # noqa: BLE001 - no resolvable credentials
        print(
            "[generate] No Anthropic credentials available - skipping generation. "
            "Set ANTHROPIC_API_KEY (repo secret in CI) to enable drafting.",
            file=sys.stderr,
        )
        return []

    try:
        response = client.messages.create(
            model=model,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            system=_SYSTEM,
            messages=[{"role": "user", "content": _build_prompt(threats, allowed)}],
            output_config={"format": {"type": "json_schema", "schema": _DETECTION_SCHEMA}},
        )
    except anthropic.AuthenticationError:
        print(
            "[generate] No Anthropic credentials available - skipping generation. "
            "Set ANTHROPIC_API_KEY (repo secret in CI) to enable drafting.",
            file=sys.stderr,
        )
        return []
    except Exception as exc:  # noqa: BLE001
        if "authentication" in str(exc).lower() or "api_key" in str(exc).lower():
            print(
                "[generate] No Anthropic credentials available - skipping generation. "
                "Set ANTHROPIC_API_KEY (repo secret in CI) to enable drafting.",
                file=sys.stderr,
            )
        else:
            print(f"[generate] Claude request failed: {exc}", file=sys.stderr)
        return []

    if response.stop_reason == "refusal":
        print("[generate] Model declined the request.", file=sys.stderr)
        return []

    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        detections = json.loads(text).get("detections", [])
    except json.JSONDecodeError:
        print("[generate] Could not parse model output as JSON.", file=sys.stderr)
        return []

    # Keep only detections mapped to a tactic we have a folder for.
    return [d for d in detections if d.get("tactic") in allowed]
