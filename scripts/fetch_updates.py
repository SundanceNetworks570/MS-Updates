import json
import re
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.parse import quote

API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
UPDATES_URL = f"{API_BASE}/updates"

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

def classify(severity: str, title: str) -> str:
    t = (title or "").lower()
    if "preview" in t:
        return "Preview (Non-security)"
    if "out-of-band" in t or "oob" in t:
        return "Out-of-band"
    if severity and severity.lower() in ("critical", "important", "moderate", "low"):
        return "Security Update (Patch Tuesday)"
    return "Update"

def badge(severity: str, title: str) -> str:
    t = (title or "").lower()
    if "preview" in t:
        return "Preview"
    if "out-of-band" in t or "oob" in t:
        return "Important (quality)"
    if severity:
        return "Security"
    return "Update"

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

def fetch_all_updates():
    items = []
    url = UPDATES_URL + "?" + "&".join([
        "$orderby=" + quote("CurrentReleaseDate desc"),
        "$top=200"
    ])

    while url:
        data = fetch_json(url)
        page_items = data.get("value", [])
        if isinstance(page_items, list):
            items.extend(page_items)
        url = data.get("@odata.nextLink")

    return items

def main():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=90)

    items = fetch_all_updates()
    out = []

    for item in items:
        date_str = item.get("InitialReleaseDate") or item.get("CurrentReleaseDate")
        if not date_str:
            continue

        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            continue

        if dt < start or dt > end:
            continue

        title = (item.get("DocumentTitle") or item.get("Title") or "").strip()
        severity = (item.get("Severity") or "").strip()
        cvrf_url = (item.get("CvrfUrl") or item.get("Url") or "").strip()

        kb_match = re.search(r"\bKB\d{6,8}\b", title)
        kb = kb_match.group(0) if kb_match else (item.get("ID") or "KB-Unknown")

        products = item.get("Products") or []
        if isinstance(products, str):
            products = [products]

        if not products:
            products = ["Microsoft Products"]

        for p in products:
            out.append({
                "date": dt.date().isoformat(),
                "kb": kb,
                "product": normalize_product(p),
                "classification": classify(severity, title),
                "details": title or "Security update",
                "known_issues": "See Microsoft release notes / CVRF for details.",
                "link": cvrf_url or "https://msrc.microsoft.com/update-guide",
                "severity": badge(severity, title)
            })

    out.sort(key=lambda x: x["date"], reverse=True)

    with open("updates.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print(f"Wrote {len(out)} updates to updates.json")

if __name__ == "__main__":
    main()
