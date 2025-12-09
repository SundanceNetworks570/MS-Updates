#!/usr/bin/env python3
import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timedelta, date
from typing import Any, Dict, List, Set, Tuple

MSRC_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/"
UA = "Mozilla/5.0 (MS-Updates GitHub Action)"

KB_RE = re.compile(r"\bKB\s*([0-9]{6,8})\b", re.IGNORECASE)

def fetch_json(url: str, timeout: int = 30) -> Any:
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/json"
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8", errors="replace")
        return json.loads(raw)

def month_id(dt: date) -> str:
    return dt.strftime("%Y-%b")  # e.g., 2025-Dec

def iter_months_in_last_n_days(n_days: int) -> List[date]:
    """Return list of month-start dates that overlap last n_days."""
    end = date.today()
    start = end - timedelta(days=n_days)

    months = []
    cur = date(start.year, start.month, 1)
    while cur <= end:
        months.append(cur)
        # advance 1 month
        if cur.month == 12:
            cur = date(cur.year + 1, 1, 1)
        else:
            cur = date(cur.year, cur.month + 1, 1)
    return months

def second_tuesday(year: int, month: int) -> date:
    """Compute Patch Tuesday (second Tuesday) for given month."""
    d = date(year, month, 1)
    # weekday(): Mon=0,..Sun=6; Tue=1
    while d.weekday() != 1:
        d += timedelta(days=1)
    # first Tuesday found; add 7 for second Tuesday
    return d + timedelta(days=7)

def kb_to_catalog_link(kb: str) -> str:
    """
    Turn 'KB5066586' into a Microsoft Update Catalog search URL.
    """
    if not kb:
        return ""
    m = re.search(r"KB\s*(\d+)", kb.upper())
    if not m:
        return ""
    num = m.group(1)
    return f"https://www.catalog.update.microsoft.com/Search.aspx?q=KB{num}"

def scan_for_kbs(obj: Any, found: Set[str]) -> None:
    """Recursively scan any JSON-like structure for KB patterns."""
    if obj is None:
        return
    if isinstance(obj, str):
        for m in KB_RE.finditer(obj):
            found.add("KB" + m.group(1))
        return
    if isinstance(obj, dict):
        for v in obj.values():
            scan_for_kbs(v, found)
        return
    if isinstance(obj, list):
        for item in obj:
            scan_for_kbs(item, found)
        return

def build_rows_for_month(cvrf_month: date) -> List[Dict[str, str]]:
    mid = month_id(cvrf_month)
    cvrf_url = MSRC_BASE + mid

    try:
        data = fetch_json(cvrf_url)
    except Exception as e:
        print(f"Error: Failed fetching CVRF {mid}: {e}", file=sys.stderr)
        return [{
            "date": str(cvrf_month),
            "kb": mid,
            "product": "Microsoft Products",
            "classification": "Update",
            "details": f"{mid} Security Updates (CVRF fetch failed)",
            "known_issues": "CVRF fetch error.",
            "link": cvrf_url,
            "severity": "Update"
        }]

    found: Set[str] = set()
    scan_for_kbs(data, found)

    if not found:
        return [{
            "date": str(cvrf_month),
            "kb": mid,
            "product": "Microsoft Products",
            "classification": "Update",
            "details": f"{mid} Security Updates (JSON parsed, but no KBs found)",
            "known_issues": "See Microsoft release notes / CVRF for details.",
            "link": cvrf_url,
            "severity": "Update"
        }]

    pt = second_tuesday(cvrf_month.year, cvrf_month.month)
    pt_str = pt.isoformat()

    rows = []
    for kb in sorted(found):
        rows.append({
            "date": pt_str,
            "kb": kb,
            "product": "Microsoft Products",
            "classification": "Security Update (Patch Tuesday)",
            "details": f"{cvrf_month.strftime('%B %Y')} Security Updates (KB extracted from JSON scan)",
            "known_issues": "See Microsoft release notes / CVRF for details.",
            "link": kb_to_catalog_link(kb) or cvrf_url,
            "severity": "Security"
        })
    return rows

def dedupe_rows(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen: Set[Tuple[str, str, str]] = set()
    out: List[Dict[str, str]] = []
    for r in rows:
        key = (r.get("date", ""), r.get("kb", ""), r.get("product", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    out.sort(key=lambda x: x.get("date", ""), reverse=True)
    return out

def main():
    months = iter_months_in_last_n_days(90)

    all_rows: List[Dict[str, str]] = []
    for m in months:
        all_rows.extend(build_rows_for_month(m))

    deduped = dedupe_rows(all_rows)

    out_path = "updates.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(deduped, f, indent=2)

    print(f"Wrote {len(deduped)} updates to {out_path}")

if __name__ == "__main__":
    main()
