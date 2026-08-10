"""Pull fresh threat intelligence and normalize it for the detection generator.

Currently supports the CISA Known Exploited Vulnerabilities (KEV) catalog, a
free, no-auth JSON feed updated as vulnerabilities are observed being exploited
in the wild. Add more sources by writing another `_fetch_*` function that returns
a list of the normalized dicts described in `normalize()`.
"""
from __future__ import annotations

import datetime as dt
import sys

import requests

USER_AGENT = "KQL-Rules-detection-refresh/1.0 (+https://github.com/4p3Ir0n/KQL-Rules)"


def _fetch_cisa_kev(url: str, lookback_days: int) -> list[dict]:
    """Return CISA KEV entries added within the lookback window, normalized."""
    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=60)
    resp.raise_for_status()
    catalog = resp.json()

    cutoff = dt.date.today() - dt.timedelta(days=lookback_days)
    out: list[dict] = []
    for v in catalog.get("vulnerabilities", []):
        try:
            date_added = dt.date.fromisoformat(v["dateAdded"])
        except (KeyError, ValueError):
            continue
        if date_added < cutoff:
            continue
        out.append(
            {
                "source": "CISA KEV",
                "id": v.get("cveID", "UNKNOWN"),
                "title": v.get("vulnerabilityName", ""),
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "description": v.get("shortDescription", ""),
                "required_action": v.get("requiredAction", ""),
                "known_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                "date_added": v["dateAdded"],
            }
        )
    return out


def gather(config: dict) -> list[dict]:
    """Collect normalized threats from every enabled source in config."""
    lookback = int(config.get("lookback_days", 3))
    threats: list[dict] = []
    sources = config.get("sources", {})

    kev = sources.get("cisa_kev", {})
    if kev.get("enabled"):
        try:
            threats.extend(_fetch_cisa_kev(kev["url"], lookback))
        except Exception as exc:  # noqa: BLE001 - a bad source shouldn't kill the run
            print(f"[ingest] CISA KEV fetch failed: {exc}", file=sys.stderr)

    # Newest first, then cap to keep PRs reviewable.
    threats.sort(key=lambda t: t.get("date_added", ""), reverse=True)
    cap = int(config.get("max_threats_per_run", 8))
    return threats[:cap]


if __name__ == "__main__":  # quick manual smoke test
    import json
    import pathlib

    import yaml

    cfg = yaml.safe_load((pathlib.Path(__file__).parent / "config.yaml").read_text())
    result = gather(cfg)
    print(f"Gathered {len(result)} threat(s):")
    print(json.dumps(result, indent=2)[:4000])
