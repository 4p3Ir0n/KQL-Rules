"""Pull fresh threat intelligence from multiple sources and normalize it.

Every source emits the same normalized dict so the generator can reason over a
mixed feed:

    {
      "source":  str,   # e.g. "CISA KEV", "abuse.ch ThreatFox", "SigmaHQ", "Vendor RSS: Unit 42"
      "kind":    str,   # "vulnerability" | "ioc_family" | "sigma_rule" | "threat_report"
      "id":      str,
      "title":   str,
      "date":    str,   # ISO date (YYYY-MM-DD), used for sorting/capping
      "summary": str,   # human-readable context the model reads
      "details": dict,  # kind-specific structured extras
    }

Add a source by writing another `_fetch_*` function returning that shape and
registering it in `gather()`. Any source that raises is logged and skipped so a
single bad feed never kills the run.
"""
from __future__ import annotations

import datetime as dt
import os
import sys

import requests
import yaml

USER_AGENT = "KQL-Rules-detection-refresh/1.0 (+https://github.com/4p3Ir0n/KQL-Rules)"


def _today() -> dt.date:
    return dt.date.today()


# --------------------------------------------------------------------------- #
# Source 1: CISA KEV (actively-exploited CVEs)
# --------------------------------------------------------------------------- #
def _fetch_cisa_kev(cfg: dict, lookback_days: int) -> list[dict]:
    resp = requests.get(cfg["url"], headers={"User-Agent": USER_AGENT}, timeout=60)
    resp.raise_for_status()
    catalog = resp.json()

    cutoff = _today() - dt.timedelta(days=lookback_days)
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
                "kind": "vulnerability",
                "id": v.get("cveID", "UNKNOWN"),
                "title": v.get("vulnerabilityName", ""),
                "date": v["dateAdded"],
                "summary": v.get("shortDescription", ""),
                "details": {
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "required_action": v.get("requiredAction", ""),
                    "known_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                },
            }
        )
    out.sort(key=lambda t: t["date"], reverse=True)
    return out[: int(cfg.get("max_items", 6))]


# --------------------------------------------------------------------------- #
# Source 2: abuse.ch ThreatFox (fresh IOCs, aggregated by malware family)
# --------------------------------------------------------------------------- #
def _fetch_abuse_ch(cfg: dict, lookback_days: int) -> list[dict]:
    auth_key = os.environ.get("ABUSE_CH_AUTH_KEY")
    if not auth_key:
        print(
            "[ingest] abuse.ch skipped - set ABUSE_CH_AUTH_KEY (free account key) "
            "to enable ThreatFox.",
            file=sys.stderr,
        )
        return []

    days = max(1, min(lookback_days, 7))  # ThreatFox get_iocs accepts 1-7
    resp = requests.post(
        cfg["url"],
        headers={"User-Agent": USER_AGENT, "Auth-Key": auth_key},
        json={"query": "get_iocs", "days": days},
        timeout=60,
    )
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("query_status") != "ok":
        print(f"[ingest] abuse.ch query_status={payload.get('query_status')}", file=sys.stderr)
        return []

    # Aggregate IOCs by malware family so we can prompt for behavioral detections
    # rather than dumping raw, short-lived indicators.
    families: dict[str, dict] = {}
    for ioc in payload.get("data", []):
        fam = ioc.get("malware_printable") or ioc.get("malware") or "Unknown"
        agg = families.setdefault(
            fam,
            {"count": 0, "ioc_types": set(), "tags": set(), "threat_types": set(), "last_seen": ""},
        )
        agg["count"] += 1
        if ioc.get("ioc_type_desc") or ioc.get("ioc_type"):
            agg["ioc_types"].add(ioc.get("ioc_type_desc") or ioc.get("ioc_type"))
        if ioc.get("threat_type_desc") or ioc.get("threat_type"):
            agg["threat_types"].add(ioc.get("threat_type_desc") or ioc.get("threat_type"))
        for tag in ioc.get("tags") or []:
            agg["tags"].add(tag)
        seen = (ioc.get("first_seen") or "")[:10]
        agg["last_seen"] = max(agg["last_seen"], seen)

    out: list[dict] = []
    for fam, agg in families.items():
        ioc_types = ", ".join(sorted(agg["ioc_types"])) or "unknown"
        threat_types = ", ".join(sorted(agg["threat_types"])) or "unknown"
        tags = ", ".join(sorted(agg["tags"])[:12])
        out.append(
            {
                "source": "abuse.ch ThreatFox",
                "kind": "ioc_family",
                "id": f"threatfox:{fam}",
                "title": f"{fam} — {agg['count']} fresh IOC(s)",
                "date": agg["last_seen"] or _today().isoformat(),
                "summary": (
                    f"Malware family '{fam}' with {agg['count']} recently reported "
                    f"indicator(s). IOC types: {ioc_types}. Threat types: {threat_types}."
                    + (f" Tags: {tags}." if tags else "")
                ),
                "details": {"family": fam, "ioc_count": agg["count"], "tags": sorted(agg["tags"])[:12]},
            }
        )
    out.sort(key=lambda t: (t["details"]["ioc_count"], t["date"]), reverse=True)
    return out[: int(cfg.get("max_items", 4))]


# --------------------------------------------------------------------------- #
# Source 3: SigmaHQ (recently added/changed community detection rules)
# --------------------------------------------------------------------------- #
def _github_headers() -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_sigmahq(cfg: dict, lookback_days: int) -> list[dict]:
    repo = cfg.get("repo", "SigmaHQ/sigma")
    products = {p.lower() for p in cfg.get("logsource_products", ["windows"])}
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=lookback_days)).isoformat()
    headers = _github_headers()

    commits = requests.get(
        f"https://api.github.com/repos/{repo}/commits",
        headers=headers,
        params={"since": since, "path": "rules", "per_page": 100},
        timeout=60,
    )
    commits.raise_for_status()

    # Collect unique rule files touched since the cutoff (newest commit wins).
    candidates: dict[str, str] = {}  # path -> commit sha
    for commit in commits.json()[:30]:
        sha = commit.get("sha")
        if not sha:
            continue
        detail = requests.get(
            f"https://api.github.com/repos/{repo}/commits/{sha}", headers=headers, timeout=60
        )
        if detail.status_code != 200:
            continue
        for f in detail.json().get("files", []):
            path = f.get("filename", "")
            if (
                path.startswith("rules/")
                and path.endswith(".yml")
                and f.get("status") in ("added", "modified")
                and path not in candidates
            ):
                candidates[path] = sha
        if len(candidates) >= int(cfg.get("max_items", 4)) * 4:
            break

    out: list[dict] = []
    for path, sha in candidates.items():
        raw = requests.get(
            f"https://raw.githubusercontent.com/{repo}/{sha}/{path}",
            headers={"User-Agent": USER_AGENT},
            timeout=60,
        )
        if raw.status_code != 200:
            continue
        try:
            rule = yaml.safe_load(raw.text)
        except yaml.YAMLError:
            continue
        if not isinstance(rule, dict) or "detection" not in rule:
            continue

        logsource = rule.get("logsource", {}) or {}
        product = (logsource.get("product") or "").lower()
        if product and product not in products:
            continue  # skip platforms we don't cover (linux/macos/cloud unless configured)

        tags = [t for t in (rule.get("tags") or []) if str(t).startswith("attack.")]
        out.append(
            {
                "source": "SigmaHQ",
                "kind": "sigma_rule",
                "id": rule.get("id", path),
                "title": rule.get("title", path.rsplit("/", 1)[-1]),
                "date": _today().isoformat(),
                "summary": (rule.get("description") or "").strip()
                or f"Sigma rule {rule.get('title', path)}",
                "details": {
                    "logsource": logsource,
                    "attack_tags": tags,
                    "detection_yaml": yaml.safe_dump(
                        rule.get("detection", {}), sort_keys=False
                    ).strip(),
                    "path": path,
                },
            }
        )
        if len(out) >= int(cfg.get("max_items", 4)):
            break
    return out


# --------------------------------------------------------------------------- #
# Source 4: Vendor RSS / Atom threat-intel feeds
# --------------------------------------------------------------------------- #
def _fetch_vendor_rss(cfg: dict, lookback_days: int) -> list[dict]:
    try:
        import feedparser
    except ImportError:
        print("[ingest] vendor_rss skipped - `feedparser` not installed.", file=sys.stderr)
        return []

    cutoff = _today() - dt.timedelta(days=lookback_days)
    out: list[dict] = []
    for feed in cfg.get("feeds", []):
        name, url = feed.get("name", "feed"), feed.get("url")
        if not url:
            continue
        try:
            parsed = feedparser.parse(url, request_headers={"User-Agent": USER_AGENT})
        except Exception as exc:  # noqa: BLE001
            print(f"[ingest] RSS '{name}' failed: {exc}", file=sys.stderr)
            continue

        for entry in parsed.entries:
            struct = entry.get("published_parsed") or entry.get("updated_parsed")
            entry_date = dt.date(*struct[:3]) if struct else _today()
            if entry_date < cutoff:
                continue
            summary = (entry.get("summary") or entry.get("title") or "").strip()
            # RSS summaries can carry HTML; keep it short and let the model cope.
            summary = summary.replace("\n", " ")[:800]
            out.append(
                {
                    "source": f"Vendor RSS: {name}",
                    "kind": "threat_report",
                    "id": entry.get("link", entry.get("id", entry.get("title", "post"))),
                    "title": entry.get("title", "Untitled post"),
                    "date": entry_date.isoformat(),
                    "summary": summary,
                    "details": {"link": entry.get("link", ""), "feed": name},
                }
            )
    out.sort(key=lambda t: t["date"], reverse=True)
    return out[: int(cfg.get("max_items", 4))]


# --------------------------------------------------------------------------- #
# Merge
# --------------------------------------------------------------------------- #
_FETCHERS = {
    "cisa_kev": _fetch_cisa_kev,
    "abuse_ch": _fetch_abuse_ch,
    "sigmahq": _fetch_sigmahq,
    "vendor_rss": _fetch_vendor_rss,
}


def gather(config: dict) -> list[dict]:
    """Collect normalized threats from every enabled source, merged round-robin."""
    lookback = int(config.get("lookback_days", 3))
    sources = config.get("sources", {})

    buckets: list[list[dict]] = []
    for name, fetch in _FETCHERS.items():
        cfg = sources.get(name, {})
        if not cfg.get("enabled"):
            continue
        try:
            items = fetch(cfg, lookback)
            print(f"[ingest] {name}: {len(items)} item(s)", file=sys.stderr)
            if items:
                buckets.append(items)
        except Exception as exc:  # noqa: BLE001 - one bad source shouldn't kill the run
            print(f"[ingest] {name} fetch failed: {exc}", file=sys.stderr)

    # Round-robin merge so no single source dominates the (capped) output.
    cap = int(config.get("max_threats_per_run", 12))
    merged: list[dict] = []
    idx = 0
    while len(merged) < cap and any(idx < len(b) for b in buckets):
        for b in buckets:
            if idx < len(b):
                merged.append(b[idx])
                if len(merged) >= cap:
                    break
        idx += 1
    return merged


if __name__ == "__main__":  # quick manual smoke test
    import json
    import pathlib

    cfg = yaml.safe_load((pathlib.Path(__file__).parent / "config.yaml").read_text())
    result = gather(cfg)
    print(f"Gathered {len(result)} threat(s):")
    print(json.dumps(result, indent=2)[:6000])
