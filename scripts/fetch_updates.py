import json
import re
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen

API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
UPDATES_URL = f"{API_BASE}/updates"
CVRF_URL = f"{API_BASE}/cvrf"

KB_RE = re.compile(r"\bKB\d{6,8}\b", re.IGNORECASE)

def to_text(x) -> str:
    """Safely coerce MSRC fields into text."""
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    if isinstance(x, (int, float, bool)):
        return str(x)
    if isinstance(x, dict):
        for k in ("Value", "Text", "Title", "Description", "Name"):
            v = x.get(k)
            if isinstance(v, str) and v.strip():
                return v
        return json.dumps(x, ensure_ascii=False)
    if isinstance(x, list):
        return " ".join(to_text(i) for i in x if to_text(i))
    return str(x)

def fetch_text(url: str) -> str:
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "github-action-msrc-fetch"
        },
    )
    with urlopen(req) as r:
        return r.read().decode("utf-8", errors="replace")

def fetch_json_or_xml(url: str):
    """Try JSON. If XML, return raw XML for regex fallback."""
    raw = fetch_text(url)
    try:
        return json.loads(raw)
    except Exception as e:
        if raw.lstrip().startswith("<"):
            return {"__raw_xml": raw, "__json_error": str(e)}
        snippet = raw[:250].replace("\n", " ")
        raise RuntimeError(f"Non-JSON response and not XML. First 250 chars: {snippet}") from e

def fetch_all_update_docs():
    """Follow @odata.nextLink to get all monthly CVRF doc headers."""
    items = []
    url = UPDATES_URL
    while url:
        data = fetch_json_or_xml(url)
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
    """Build ProductID -> ProductName map from CVRF ProductTree."""
    id_to_name = {}
    try:
        full_names = product_tree.get("FullProductName", []) or []
        for p in full_names:
            pid = p.get("ProductID")
            val = to_text(p.get("Value"))
            if pid and val:
                id_to_name[pid] = val
    except Exception:
        pass
    return id_to_name

def extract_remediation_rows(remediations, id_to_name, doc_date):
    rows = []

    if isinstance(remediations, dict):
        remediations = [remediations]
    if not isinstance(remediations, list):
        return rows

    for r in remediations:
        desc = to_text(r.get("Description")).strip()
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

        r_url = to_text(r.get("URL") or r.get("Url") or r.get("Link"))

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
    url = f"{CVRF_URL}/{doc_id}"
    cvrf = fetch_json_or_xml(url)

    # ---------- XML fallback ----------
    if "__raw_xml" in cvrf:
        xml_text = cvrf["__raw_xml"]
        kb_list = sorted(set(KB_RE.findall(xml_text)))
        rows = []
        for kb in kb_list:
            rows.append({
                "date": doc_date.date().isoformat(),
                "kb": kb.upper(),
                "product": "Microsoft Products",
                "classification": "Security Update (Patch Tuesday)",
                "details": f"{doc_title} (KB extracted from XML fallback)",
                "known_issues": "See Microsoft release notes / CVRF for details.",
                "link": url,
                "severity": "Security"
            })
        if not rows:
            rows.append({
                "date": doc_date.date().isoformat(),
                "kb": doc_id,
                "product": "Microsoft Products",
                "classification": "Update",
                "details": f"{doc_title} (XML fallback, no KBs detected)",
                "known_issues": "See Microsoft release notes / CVRF for details.",
                "link": url,
                "severity": "Update"
            })
        return rows

    # ---------- JSON path ----------
    product_tree = cvrf.get("ProductTree", {}) or {}
    id_to_name = flatten_product_tree(product_tree)

    rows = []

    # 1) Top-level remediations
    rows.extend(extract_remediation_rows(cvrf.get("Remediations", []) or [], id_to_name, doc_date))

    # 2) Per-vulnerability remediations
    vulns = (
        cvrf.get("Vulnerability", [])
        or cvrf.get("Vulnerabilities", [])
        or []
    )
    if isinstance(vulns, dict):
        vulns = [vulns]

    if isinstance(vulns, list):
        for v in vulns:
            v_rems = (
                v.get("Remediations", [])
                or v.get("Remediation", [])
                or []
            )
            rows.extend(extract_remediation_rows(v_rems, id_to_name, doc_date))

    # 3) GLOBAL JSON SCAN FALLBACK (NEW)
    # If structured scraping found no KBs, scan the entire JSON blob.
    if not rows:
        blob = json.dumps(cvrf, ensure_ascii=False)
        kb_list = sorted(set(KB_RE.findall(blob)))
        for kb in kb_list:
            rows.append({
                "date": doc_date.date().isoformat(),
                "kb": kb.upper(),
                "product": "Microsoft Products",
                "classification": "Security Update (Patch Tuesday)",
                "details": f"{doc_title} (KB extracted from JSON scan)",
                "known_issues": "See Microsoft release notes / CVRF for details.",
                "link": url,
                "severity": "Security"
            })

    # If still nothing, fall back to doc-level row
    if not rows:
        rows.append({
            "date": doc_date.date().isoformat(),
            "kb": doc_id,
            "product": "Microsoft Products",
            "classification": "Update",
            "details": f"{doc_title} (JSON parsed, but no KBs found)",
            "known_issues": "See Microsoft release notes / CVRF for details.",
            "link": url,
            "severity": "Update"
        })

    return rows

def main():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=90)

    docs = fetch_all_update_docs()

    recent_docs = []
    for d in docs:
        date_str = d.get("InitialReleaseDate") or d.get("CurrentReleaseDate")
        if not date_str:
            continue

        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            continue

        if dt < start or dt > end:
            continue

        title_raw = d.get("DocumentTitle") or d.get("Title") or ""
        title = to_text(title_raw).strip()
        recent_docs.append((d.get("ID"), title, dt))

    out = []
    for doc_id, title, dt in recent_docs:
        if not doc_id:
            continue
        try:
            out.extend(extract_rows_from_cvrf(doc_id, title, dt))
        except Exception as e:
            print(f"[ERROR] Failed parsing CVRF {doc_id}: {e}")
            out.append({
                "date": dt.date().isoformat(),
                "kb": doc_id,
                "product": "Microsoft Products",
                "classification": "Update",
                "details": f"{title} (CVRF parse failed)",
                "known_issues": "CVRF fetch/parse error.",
                "link": f"{CVRF_URL}/{doc_id}",
                "severity": "Update"
            })

    # Deduplicate
    seen = set()
    deduped = []
    for r in out:
        key = (r["date"], r["kb"], r["product"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    deduped.sort(key=lambda x: x["date"], reverse=True)

    with open("updates.json", "w", encoding="utf-8") as f:
        json.dump(deduped, f, indent=2)

    print(f"Wrote {len(deduped)} updates to updates.json")

if __name__ == "__main__":
    main()
