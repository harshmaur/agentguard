#!/usr/bin/env python3
"""Refresh the reviewed AI-agent/MCP package advisory DB.

Design goals:
- Preserve older data. Existing advisories are never dropped by this script.
- Stay scoped to AUDR's wedge: AI-agent/MCP/local developer-machine package CVEs.
- Use reviewed repo data first. The CVE ledger is the human/agent-reviewed source
  of truth that filters NVD noise before a CVE reaches the scanner database.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "internal/rules/builtin/advisories/agent-packages.json"
LEDGER_PATH = ROOT / "docs/cve-triage-ledger.json"

PACKAGE_HINTS = [
    ("npm", "@anthropic-ai/sdk", re.compile(r"@anthropic-ai/sdk", re.I)),
    ("npm", "automagik-genie", re.compile(r"automagik-genie", re.I)),
    ("npm", "cloudbase-mcp", re.compile(r"(?:cloudbase-mcp|cloudbase mcp)", re.I)),
    ("npm", "directus-mcp", re.compile(r"directus-mcp", re.I)),
    ("npm", "mcp-chat-studio", re.compile(r"mcp-chat-studio", re.I)),
    ("npm", "n8n-mcp", re.compile(r"n8n-mcp", re.I)),
    ("npm", "openclaw", re.compile(r"openclaw", re.I)),
    ("npm", "xhs-mcp", re.compile(r"xhs-mcp", re.I)),
    ("pypi", "praisonaiagents", re.compile(r"praisonaiagents", re.I)),
    ("pypi", "praisonai", re.compile(r"\bpraisonai\b", re.I)),
]

WEAKNESS_TAGS = [
    ("ssrf", re.compile(r"server-side request forgery|\bSSRF\b", re.I)),
    ("sql-injection", re.compile(r"sql injection|sqlite|postgresql|mysql", re.I)),
    ("command-injection", re.compile(r"command injection|arbitrary code execution|execute arbitrary", re.I)),
    ("auth-bypass", re.compile(r"authentication bypass|authorization bypass|access control", re.I)),
    ("file-access", re.compile(r"file read|file-handling|local file|path traversal", re.I)),
    ("filesystem-permissions", re.compile(r"file mode|permissions|0o", re.I)),
    ("env", re.compile(r"environment variable|dotenv|\.env", re.I)),
]


def load_db() -> dict[str, Any]:
    if DB_PATH.exists():
        return json.loads(DB_PATH.read_text())
    return {"schema_version": 1, "source": "reviewed AUDR package advisory DB", "advisories": []}


def load_ledger_entries() -> list[dict[str, Any]]:
    data = json.loads(LEDGER_PATH.read_text())
    if isinstance(data, list):
        return data
    return data.get("entries", [])


def entry_text(entry: dict[str, Any]) -> str:
    fields = [
        entry.get("cve_id", ""),
        entry.get("vendor", ""),
        entry.get("product", ""),
        entry.get("summary", ""),
        entry.get("proposed_detection_surface", ""),
        entry.get("reason", ""),
        entry.get("next_action", ""),
    ]
    return "\n".join(str(f) for f in fields if f)


def package_mentions(text: str) -> list[tuple[str, str]]:
    out = []
    for ecosystem, package, pattern in PACKAGE_HINTS:
        if pattern.search(text):
            out.append((ecosystem, package))
    # Avoid double-adding PraisonAI when the entry is explicitly praisonaiagents-only.
    if ("pypi", "praisonaiagents") in out and not re.search(r"\bpraisonai\s+(?:version|before|prior|package)", text, re.I):
        out = [p for p in out if p != ("pypi", "praisonai")]
    return out


def version_for_package(text: str, package: str) -> dict[str, str]:
    escaped = re.escape(package)
    nearby = text
    idx = re.search(escaped, text, re.I)
    if idx:
        start = max(0, idx.start() - 160)
        end = min(len(text), idx.end() + 240)
        nearby = text[start:end]

    # versions A through B means the upper bound is still vulnerable.
    m = re.search(r"v?(\d+(?:\.\d+){1,3})\s+(?:through|to)\s+v?(\d+(?:\.\d+){1,3})", nearby, re.I)
    if m and not re.search(r"before\s+v?" + re.escape(m.group(2)), nearby, re.I):
        return {"min_version": m.group(1), "last_vulnerable": m.group(2)}

    # from version A to before B
    m = re.search(r"(?:from\s+version\s+|versions?\s+)?v?(\d+(?:\.\d+){1,3})\s+(?:to\s+)?before\s+v?(\d+(?:\.\d+){1,3})", nearby, re.I)
    if m:
        return {"min_version": m.group(1), "fixed_version": m.group(2)}

    # prior to / before / < fixed
    m = re.search(r"(?:prior to(?:\s+versions?)?|before|<)\s+v?(\d+(?:\.\d+){1,3})", nearby, re.I)
    if m:
        return {"fixed_version": m.group(1)}

    # <= last vulnerable
    m = re.search(r"(?:<=|up to(?: and including)?)\s+v?(\d+(?:\.\d+){1,3})", nearby, re.I)
    if m:
        return {"last_vulnerable": m.group(1)}

    # exact package version, e.g. xhs-mcp 0.8.11
    m = re.search(escaped + r"\s+v?(\d+(?:\.\d+){1,3})\b", nearby, re.I)
    if m:
        return {"exact_version": m.group(1)}

    return {}


def severity(entry: dict[str, Any]) -> str:
    raw = str(entry.get("severity") or entry.get("cvss_severity") or "").lower()
    if raw in {"critical", "high", "medium", "low"}:
        return raw
    text = entry_text(entry)
    if re.search(r"critical|CVSS\s*9|\b9\.\d\b", text, re.I):
        return "critical"
    return "high"


def tags_for(text: str, ecosystem: str, package: str) -> list[str]:
    tags = {ecosystem}
    if "mcp" in package.lower() or re.search(r"\bMCP\b|Model Context Protocol", text):
        tags.add("mcp")
    if package.startswith("praisonai"):
        tags.add("praisonai")
    if package == "openclaw":
        tags.add("openclaw")
    if package.startswith("@anthropic-ai"):
        tags.add("anthropic")
    for tag, pattern in WEAKNESS_TAGS:
        if pattern.search(text):
            tags.add(tag)
    return sorted(tags)


def make_title(entry: dict[str, Any], package: str) -> str:
    cve = entry.get("cve_id", "CVE")
    summary = str(entry.get("summary") or "").strip().split(".")[0]
    if len(summary) > 140:
        summary = summary[:137].rstrip() + "..."
    if not summary:
        summary = f"{package} package has a known AI-agent/MCP vulnerability"
    return f"{package} package matches {cve}: {summary}"


def merge_sources(existing: list[str], source: str) -> list[str]:
    vals = set(existing or [])
    vals.add(source)
    return sorted(vals)


def main() -> None:
    db = load_db()
    existing = db.get("advisories", [])
    by_key = {(a["ecosystem"], a["package"], a["cve"]): dict(a) for a in existing}
    added = 0
    skipped_no_range = 0

    for entry in load_ledger_entries():
        if entry.get("status") not in {"actionable", "shipped"}:
            continue
        text = entry_text(entry)
        if not re.search(r"package|manifest|lockfile|dependency|requirements|pyproject|npm|pypi", text, re.I):
            continue
        cve = entry.get("cve_id")
        if not cve:
            continue
        for ecosystem, package in package_mentions(text):
            ranges = version_for_package(text, package)
            if not ranges:
                skipped_no_range += 1
                continue
            key = (ecosystem, package, cve)
            adv = by_key.get(key, {})
            if not adv:
                added += 1
            adv.update(
                {
                    "ecosystem": ecosystem,
                    "package": package,
                    "cve": cve,
                    "title": adv.get("title") or make_title(entry, package),
                    "severity": adv.get("severity") or severity(entry),
                    "tags": sorted(set(adv.get("tags", [])) | set(tags_for(text, ecosystem, package))),
                    "sources": merge_sources(adv.get("sources", []), "docs/cve-triage-ledger.json"),
                }
            )
            for field in ["fixed_version", "last_vulnerable", "exact_version", "min_version"]:
                adv.pop(field, None)
            for field in ["fixed_version", "last_vulnerable", "exact_version", "min_version"]:
                if ranges.get(field):
                    adv[field] = ranges[field]
            by_key[key] = adv

    advisories = sorted(by_key.values(), key=lambda a: (a["ecosystem"], a["package"], a["cve"]))
    old_advisories = sorted(db.get("advisories", []), key=lambda a: (a["ecosystem"], a["package"], a["cve"]))
    generated_at = db.get("generated_at") if old_advisories == advisories else datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    db = {
        "schema_version": db.get("schema_version", 1),
        "generated_at": generated_at,
        "source": "Reviewed AUDR CVE ledger plus preserved historical package advisories. Runtime scanner is offline.",
        "advisories": advisories,
    }
    DB_PATH.write_text(json.dumps(db, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {DB_PATH.relative_to(ROOT)} with {len(advisories)} advisories ({added} new, {skipped_no_range} skipped without exact/fixed range)")


if __name__ == "__main__":
    main()
