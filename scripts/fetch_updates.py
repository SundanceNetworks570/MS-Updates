import json
import re
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen

API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
UPDATES_URL = f"{API_BASE}/updates"
CVRF_URL = f"{API_BASE}/cvrf"

KB_RE = re.compile(r"\bKB\d{6,8}\b", re.IGNORECASE)

def fetch_json(url: str) -> dict:
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "github-action-msrc-fetch"
        },
    )
    with urlopen(req) as r:
        return json.load(r)

def fetch_all_update_docs():
    """Follow @odata.nextLink to get ALL monthly CVRF doc headers."""
    items = []
    url = UPDATES_URL
    while url:
        data = fetch_json(url)
        page_items = data.get("value", [])
        if isinstance(page_items, list):
            items.extend(page_items)
        url = data.get("@odata.nextLink")
    return items

def normalize_product(raw: str) -> str:
    r = (raw or "").lower()

    if "windows 11" in r:
        if "24h2" in r or "25h2" in r:
            return "Windows 11 24H2 / 25H2"
        if "23h2" in r or "22h2" in r:
            return "Windows 11 22H2 / 23H2"
        return "Windows 11"

    if "windows 10" in r:
        return "Windows 10 21H2 / 22H2 (incl. LTSC 2021)"

    if "windows server 2022" in r:
        return "Windows Server 2022"
    if "windows server 2019" in r:
        return "Windows Server 2019"
    if "windows server 2016" in r:
        return "Windows Server 2016"

    return raw or "Other"

def flatten_product_tree(product_tree: dict) -> dict:
    """
    Build ProductID -> ProductName map from CVRF ProductTree.
    CVRF nests products; FullProductName is the reliable ProductID map.
    """
    id_to_name = {}
    try:
        full_names = product_tree.get("FullProductName", []) or []
        for p in full_names:
            pid = p.get("ProductID")
            val = p.get("Value")
            if pid and val:
                id_to_name[pid] = val
    except Exception:
        pass
    return id_to_name

def extract_remediation_rows(remediations, id_to_name, doc_date):
    """
    Extract KB rows from a list of remediation objects.
    Handles ProductID/ProductIDs variants.
    """
    rows = []
    if not isinstance(remediations, list):
        return rows

    for r in remediations:
        desc = (r.get("Description") or "").strip()
        if not desc:
            continue

        kb_match = KB_RE.search(desc)
        if not kb_match:
            continue

        kb = kb_match.group(0).upper()

        pids = []
        if isinstance(r.get("ProductID"), str):
            pids = [r.get("ProductID")]
        elif isinstance(r.get("ProductIDs"), list):
            pids = r.get("ProductIDs")
        elif isinstance(r.get("ProductIDs"), str):
            pids = [r.get("ProductIDs")]

        if not pids:
            pids = [None]

        r_url = r.get("URL") or r.get("Url") or r.get("Link") or ""

        for pid in pids:
            pname_raw = id_to_name.get(pid, "Microsoft Products")
            pname = normalize_product(pname_raw)

            rows.append({
                "date": doc_date.date().isoformat(),
                "kb": kb,
                "product": pname,
                "classification": "Security Update (Patch Tuesday)",
                "details": desc if len(desc) < 280 else (desc[:277] + "..."),
                "known_issues": "See Microsoft release notes / CVRF for details.",
                "link": r_url or "https://msrc.microsoft.com/update-guide",
                "severity": "Security"
            })

    return rows

def extract_rows_from_cvrf(doc_id: str, doc_title: str, doc_date: datetime) -> list:
    """
    Download CVRF doc and extract KBs from:
      1) Top-level Remediations
      2) Vulnerability-level Remediations (most common place)
    """
    url = f"{CVRF_URL}/{doc_id}"
    cvrf = fetch_json(url)

    product_tree = cvrf.get("ProductTree", {}) or {}
    id_to_name = flatten_product_tree(product_tree)

    rows = []

    # 1) Top-level Remediations
    rows.extend(extract_remediation_rows(cvrf.get("Remediations", []), id_to_name, doc_date))

    # 2) Vulnerability-level Remediations
    vulns = cvrf.get("Vulnerability", []) or cvrf.get("Vulnerabilities", []) or []
    if isinstance(vulns, list):
        for v in vulns:
            v_rems = v.get("Remediations", []) or v.get("Remediation", []) or []
            rows.extend(extract_remediation_rows(v_rems, id_to_name, doc_date))

    # If still nothing, fall back to a doc-level row
    if not rows:
        rows.append({
            "date": doc_date.date().isoformat(),
            "kb": doc_id,
            "product": "Microsoft Products",
            "classification": "Update",
            "details": doc_title or "Security updates",
            "known_i_
