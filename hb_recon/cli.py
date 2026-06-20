import os
import re
import json
import subprocess
import time
import concurrent.futures
from urllib.parse import urlparse, parse_qs
import platform
import sys

# Platform detection
IS_WINDOWS = platform.system() == 'Windows'
if IS_WINDOWS:
    print('[!] Error: hb-recon requires Linux/WSL environment')
    print('[!] Tools required: subfinder, httpx, katana, gf, whatweb')
    print('[!] Install on WSL/Linux or use docker')
    sys.exit(1)

# Auto-detect tool paths
def find_tool(tool_name):
    """Find tool in PATH, ~/go/bin, or /usr/bin"""
    # Try shutil.which first (checks PATH)
    import shutil
    tool_path = shutil.which(tool_name)
    if tool_path:
        return tool_path
    
    # Try ~/go/bin
    go_path = os.path.expanduser(f"~/go/bin/{tool_name}")
    if os.path.exists(go_path):
        return go_path
    
    # Try /usr/bin
    usr_path = f"/usr/bin/{tool_name}"
    if os.path.exists(usr_path):
        return usr_path
    
    # Fallback to tool name (will fail if not in PATH)
    return tool_name

# Tool paths
SUBFINDER = find_tool("subfinder")
HTTPX = find_tool("httpx") or find_tool("httpx-toolkit")
KATANA = find_tool("katana")
GF = find_tool("gf")
WHATWEB = find_tool("whatweb")

("~/go/bin")


# ---------------------------------------------------------------------------
def run(cmd, step="", timeout=300, outfile=None):
    print(f"\n[+] {step}" if step else "")
    st = time.time()
    try:
        if outfile:
            with open(outfile, "w") as f:
                p = subprocess.Popen(cmd, shell=True, executable="/bin/bash",
                                     stdout=f, stderr=subprocess.PIPE, text=True)
                for ln in p.stderr:
                    if s := ln.strip():
                        print(f"    {s}")
                p.wait(timeout=timeout)
        else:
            subprocess.run(cmd, shell=True, executable="/bin/bash",
                           timeout=timeout)
        print(f"[v] Done ({round(time.time()-st,1)}s)")
    except subprocess.TimeoutExpired:
        print(f"[x] Timeout after {timeout}s")


# ---------------------------------------------------------------------------
def extract_params(urls):
    """Break URLs into endpoint + params + file_type"""
    endpoints, params_map, file_types, post_params, js_files = [], {}, set(), {}, []
    for u in urls:
        u = u.strip()
        if not u or not u.startswith("http"):
            continue
        parsed = urlparse(u)
        path = parsed.path

        # track JS files separately
        if path.endswith(".js") and "/_next/" not in path:
            js_files.append(u)

        # detect file types (before filtering)
        if "." in path:
            ext = path.rsplit(".", 1)[-1].lower()
            if ext in ("js","json","xml","yml","env","bak","sql","php","aspx","jsp"):
                file_types.add(ext)

        # skip static assets and CDN clutter
        if re.search(r"/_next/|/static/|/cdn-cgi/|\.(css|png|jpg|ico|svg|woff|woff2|ttf|map|webp)$", path, re.I):
            continue
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        endpoints.append(base)

        # query params
        qp = parse_qs(parsed.query)
        for k in qp:
            params_map.setdefault(k, []).append(u)

        # detect POST params from common patterns
        if any(w in u.lower() for w in ["login","signup","register","upload","reset","search"]):
            post_params.setdefault("_suspected_post", []).append(u)

    return {
        "endpoints": sorted(set(endpoints)),
        "params": {k: sorted(set(v)) for k, v in params_map.items()},
        "file_types": sorted(file_types),
        "suspected_post_forms": sorted(set(post_params.get("_suspected_post", []))),
        "js_files": sorted(set(js_files))
    }


def categorize(endpoints):
    """Group endpoints by type"""
    cats = {
        "login": [], "api": [], "admin": [], "upload": [],
        "redirect": [], "search": [], "config": [], "other": []
    }
    patterns = {
        "login":    r"(login|signin|auth|sso|oauth)",
        "api":      r"(/api/|/graphql|/v\d+/|/rest/)",
        "admin":    r"(admin|dashboard|panel|wp-admin|cpanel)",
        "upload":   r"(upload|import|attachment)",
        "redirect": r"(redirect|callback|return_to|url=|dest=|next=)",
        "search":   r"[/?](search|find)[/?]|search\?",
        "config":   r"(\.env|\.git|\.bak|config|debug|phpinfo)",
    }
    for ep in endpoints:
        matched = False
        for cat, pat in patterns.items():
            if re.search(pat, ep, re.I):
                cats[cat].append(ep)
                matched = True
                break
        if not matched:
            cats["other"].append(ep)
    return {k: sorted(v) for k, v in cats.items() if v}


def risk_score(ep):
    """0-10 based on vulnerability surface"""
    # skip static assets
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


# ---------------------------------------------------------------------------
def parse_katana_output(url_file):
    """Katana output format: URL [status] [method] ..."""
    urls, meta = [], []
    with open(url_file, errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            urls.append(line.split()[0] if " " in line else line)
            meta.append(line)
    return urls, meta


# ---------------------------------------------------------------------------
def parse_whatweb(raw):
    """Parse whatweb output into tech stack dict"""
    ansi = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    raw_clean = ansi.sub('', raw)
    result = {}
    for line in raw_clean.strip().splitlines():
        # split: URL [status] tag1, tag2[val], ...
        if " [" not in line:
            continue
        # get URL and rest
        parts = line.split(" [", 1)
        url = parts[0].strip()
        rest = parts[1].split("]", 1)  # first ] after status code
        if len(rest) < 2:
            continue
        # rest[1] contains all the tags
        tags_raw = rest[1].strip().rstrip(",")

        # parse tags manually: split on ", " but respect brackets
        tech = {"server": "", "cms": "", "cdn": "", "lang": "", "headers": []}
        current = ""
        depth = 0
        tags = []
        for ch in tags_raw:
            if ch == "[":
                depth += 1
                current += ch
            elif ch == "]":
                depth -= 1
                current += ch
            elif ch == "," and depth == 0:
                tags.append(current.strip())
                current = ""
            else:
                current += ch
        if current.strip():
            tags.append(current.strip())

        for tag in tags:
            tag = tag.strip()
            if not tag:
                continue
            if "[" in tag:
                key, val = tag.split("[", 1)
                val = val.rstrip("]")
            else:
                key, val = tag, ""

            k = key.lower()
            if "httpserver" in k:
                tech["server"] = val
            elif "x-powered-by" in k:
                tech["cms"] = val
            elif k in ("cloudflare", "cloudfront"):
                tech["cdn"] = key
            elif k in ("next.js", "php", "asp_net", "laravel", "django", "ruby"):
                tech["lang"] = val or key
            elif any(h in k for h in ("x-", "strict-transport", "content-security")):
                tech["headers"].append(key)

        result[url] = {k: v for k, v in tech.items() if v}
        if "server" not in result[url] and "cms" not in result[url]:
            result[url]["server"] = "unknown"
    return result


def scan_tech(alive_file, outdir):
    """Use whatweb to detect tech stack"""
    if not os.path.exists(alive_file):
        return {}
    hosts = [l.strip() for l in open(alive_file) if l.strip().startswith("http")]
    if not hosts:
        return {}
    print("\n[*] WhatWeb (tech detection)...")
    outfile = f"{outdir}/whatweb.txt"
    cmd = f"whatweb --color=never --no-errors {' '.join(hosts)} > {outfile}"
    run(cmd, f"WhatWeb ({len(hosts)} hosts)")
    if os.path.exists(outfile):
        return parse_whatweb(open(outfile).read())
    return {}


# ---------------------------------------------------------------------------
def build_ai_report(target, d):
    report = {"target": target, "scan_date": time.strftime("%Y-%m-%d %H:%M")}

    # --- subdomains + alive ---
    subs = open(f"{d}/subdomains.txt","r").read().splitlines() if os.path.exists(f"{d}/subdomains.txt") else []
    alive = []
    if os.path.exists(f"{d}/alive.txt"):
        for ln in open(f"{d}/alive.txt"):
            ln = ln.strip()
            if ln.startswith("http"):
                alive.append({"url": ln, "status": "alive"})

    # --- katana output ---
    raw_urls, _ = parse_katana_output(f"{d}/urls.txt") if os.path.exists(f"{d}/urls.txt") else ([], [])
    ep_info = extract_params(raw_urls)
    cat = categorize(ep_info["endpoints"])

    # risk scoring
    risky = sorted([e for e in ep_info["endpoints"] if risk_score(e) > 0],
                    key=lambda x: -risk_score(x))[:20]

    # --- whatweb tech stack ---
    tech_stack = scan_tech(f"{d}/alive.txt", d)

    # --- gf patterns ---
    gf_data = {}
    for name in ["xss","sqli","idor"]:
        fp = f"{d}/{name}.txt"
        if os.path.exists(fp):
            gf_data[name] = [l.strip() for l in open(fp) if l.strip()][:30]

    # --- assemble ---
    report["summary"] = {
        "subdomains": len(subs),
        "alive_hosts": len(alive),
        "endpoints": len(ep_info["endpoints"]),
        "params_with_input": list(ep_info["params"].keys()),
        "file_types": ep_info["file_types"],
        "tech_detected": {u: t.get("cms") or t.get("cdn") or t.get("server") or "unknown" for u, t in tech_stack.items()},
        "gf_matches": {k: len(v) for k, v in gf_data.items()},
    }

    report["subdomains"] = subs
    report["alive_hosts"] = alive

    report["attack_surface"] = {
        "tech_stack": tech_stack,
        "by_category": cat,
        "top_risky_endpoints": [{"url": u, "score": risk_score(u)} for u in risky],
        "query_params": ep_info["params"],
        "suspected_post_forms": ep_info["suspected_post_forms"],
        "interesting_files": ep_info["file_types"],
        "js_files": ep_info["js_files"][:30],
    }

    report["vulnerabilities"] = {
        "gf_pattern_matches": gf_data,
    }

    report["suggestions"] = generate_suggestions(report, target)

    with open(f"{d}/ai_ready.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[+] AI Report saved: {d}/ai_ready.json")
    print_summary(report)


def generate_suggestions(r, t):
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

    # tech-specific suggestions
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


def print_summary(r):
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


# ---------------------------------------------------------------------------
def main():
    print("=" * 55)
    print("  Auto Recon -> AI Ready")
    print("=" * 55)

    target = input("\n[>] Domain: ").strip()
    if not target:
        return

    # clean input: strip https://, http://, trailing /
    target = re.sub(r'^https?://', '', target).rstrip('/')

    d = f"recon_{target}"
    os.makedirs(d, exist_ok=True)
    start = time.time()

    # Phase 1 — subfinder + httpx
    run(
        f"{SUBFINDER} -d {target} -s hackertarget,waybackarchive -silent | "
        f"tee {d}/subdomains.txt | "
        f"httpx-toolkit -mc 200,301,403 -silent > {d}/alive.txt",
        "Subfinder + Httpx"
    )

    # Phase 2 — whatweb + katana (parallel)
    print("\n[*] WhatWeb + Katana (parallel)...")
    # whatweb is already called inside build_ai_report via scan_tech()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(run, f"{KATANA} -list {d}/alive.txt -d 3 -c 15 -silent > {d}/urls.txt",
                       "Katana (crawl)")
        concurrent.futures.wait([f1])

    # Phase 3 — gf patterns
    if os.path.exists(f"{d}/urls.txt"):
        run(
            f"cat {d}/urls.txt | {GF} xss > {d}/xss.txt && "
            f"cat {d}/urls.txt | {GF} sqli > {d}/sqli.txt && "
            f"cat {d}/urls.txt | {GF} idor > {d}/idor.txt",
            "gf (XSS/SQLi/IDOR patterns)"
        )

    # Phase 4 — build AI report
    build_ai_report(target, d)

    print(f"\n[√] Total: {round(time.time()-start,1)}s")


if __name__ == "__main__":
    main()
