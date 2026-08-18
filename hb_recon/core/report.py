import os
import json
import time
import re
import logging
from hb_recon.core.parser import parse_katana_output, extract_params, categorize

logger = logging.getLogger(__name__)

def risk_score(ep: str) -> int:
    """0-10 based on vulnerability surface"""
    if re.search(r"/_next/|/static/|\.(css|js|png|jpg|ico|svg|woff|woff2|ttf|map)$", ep, re.I):
        return 0
    score = 1
    if any(w in ep.lower() for w in ["login","auth","admin","dashboard","api","upload"]):
        score += 3
    if "?" in ep:
        score += 2
    if any(w in ep.lower() for w in ["id=","user=","file=","page=","redirect=","url="]):
        score += 3
    return min(score, 10)

def generate_suggestions(r: dict, t: str) -> list:
    s = []
    ps = r["attack_surface"]["query_params"]
    cat = r["attack_surface"]["by_category"]

    if cat.get("login"):
        s.append("Brute-force / default creds on login endpoints")
    if cat.get("api"):
        s.append("Test API endpoints for auth bypass, IDOR, rate-limit")
    if cat.get("upload"):
        s.append("Test file upload for RCE, XSS, unrestricted upload")
    if cat.get("redirect"):
        s.append("Check for open redirect via redirect parameters")
    if cat.get("search"):
        s.append("Test search endpoints for reflected XSS")
    if cat.get("admin"):
        s.append("Check admin access controls, try /admin, /wp-admin")
    if any(k in ps for k in ["id","user","uid","order","pid"]):
        s.append("IDOR: try incrementing/decrementing id parameters")
    if any(k in ps for k in ["q","s","query","search","keyword"]):
        s.append("XSS: inject <script>alert(1)</script> in search/query params")
    if any(k in ps for k in ["redirect","url","return","next","dest"]):
        s.append("Open redirect: try //evil.com in redirect params")
    if any(k in ps for k in ["file","path","include","template"]):
        s.append("LFI/Path Traversal: try ../../etc/passwd in file params")
    if r["attack_surface"]["js_files"]:
        s.append("Check JS files for hidden endpoints, API keys, secrets")
    if "bak" in r["attack_surface"]["interesting_files"] or ".env" in str(r["attack_surface"]):
        s.append("Check backup/config files for exposed credentials")
    if any(w in str(r["subdomains"]).lower() for w in ["dev","staging","test","beta","uat"]):
        s.append("Dev/Staging environments often have weaker security")

    ts = r["attack_surface"]["tech_stack"]
    for host, info in ts.items():
        cms = info.get("cms","").lower()
        svr = info.get("server","").lower()
        if "next.js" in cms or "next.js" in info.get("lang","").lower():
            s.append(f"{host}: Next.js — check /api/, /_next/, source maps, SSR params")
        if "wordpress" in cms:
            s.append(f"{host}: WordPress — check /wp-json/, /wp-admin/, xmlrpc.php")
        if "php" in cms or "php" in svr or "php" in info.get("lang",""):
            s.append(f"{host}: PHP detected — test for LFI, PHPInfo, file upload bypass")

    return s if s else ["Analyze all endpoints for common OWASP Top 10 vulnerabilities"]

def build_ai_report(target: str, work_dir: str, tech_stack: dict):
    report = {"target": target, "scan_date": time.strftime("%Y-%m-%d %H:%M")}

    subs = []
    if os.path.exists(f"{work_dir}/subdomains.txt"):
        with open(f"{work_dir}/subdomains.txt","r") as f:
            subs = f.read().splitlines()
            
    alive = []
    if os.path.exists(f"{work_dir}/alive.txt"):
        for ln in open(f"{work_dir}/alive.txt"):
            ln = ln.strip()
            if ln.startswith("http"):
                alive.append({"url": ln, "status": "alive"})

    raw_urls, _ = parse_katana_output(f"{work_dir}/urls.txt")
    ep_info = extract_params(raw_urls)
    cat = categorize(ep_info.endpoints)

    risky = sorted([e for e in ep_info.endpoints if risk_score(e) > 0],
                    key=lambda x: -risk_score(x))[:20]

    gf_data = {}
    for name in ["xss","sqli","idor"]:
        fp = f"{work_dir}/{name}.txt"
        if os.path.exists(fp):
            gf_data[name] = [l.strip() for l in open(fp) if l.strip()][:30]

    report["summary"] = {
        "subdomains": len(subs),
        "alive_hosts": len(alive),
        "endpoints": len(ep_info.endpoints),
        "params_with_input": list(ep_info.params.keys()),
        "file_types": ep_info.file_types,
        "tech_detected": {u: t.get("cms") or t.get("cdn") or t.get("server") or "unknown" for u, t in tech_stack.items()},
        "gf_matches": {k: len(v) for k, v in gf_data.items()},
    }

    report["subdomains"] = subs
    report["alive_hosts"] = alive

    report["attack_surface"] = {
        "tech_stack": tech_stack,
        "by_category": cat,
        "top_risky_endpoints": [{"url": u, "score": risk_score(u)} for u in risky],
        "query_params": ep_info.params,
        "suspected_post_forms": ep_info.suspected_post_forms,
        "interesting_files": ep_info.file_types,
        "js_files": ep_info.js_files[:30],
    }

    report["vulnerabilities"] = {
        "gf_pattern_matches": gf_data,
    }

    report["suggestions"] = generate_suggestions(report, target)

    report_path = f"{work_dir}/ai_ready.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    logger.info(f"AI Report saved: {report_path}")
    return report

def print_summary(r: dict):
    s = r["summary"]
    print("\n" + "=" * 55)
    print(f"  Target: {r['target']}")
    print(f"  Subdomains: {s['subdomains']} | Alive: {s['alive_hosts']} | Endpoints: {s['endpoints']}")
    print(f"  Params: {s['params_with_input']}")
    print(f"  File types: {s['file_types']}")
    print(f"  Tech: {s.get('tech_detected', {})}")
    print(f"  GF matches: {s['gf_matches']}")
    print(f"  Suggestions: {len(r['suggestions'])} tips")
    print("=" * 55)
