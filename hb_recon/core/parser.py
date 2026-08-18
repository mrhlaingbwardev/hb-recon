import re
from urllib.parse import urlparse, parse_qs
from hb_recon.models import EndpointInfo

def extract_params(urls: list) -> EndpointInfo:
    """Break URLs into endpoint + params + file_type"""
    endpoints, params_map, file_types, post_params, js_files = [], {}, set(), {}, []
    
    for u in urls:
        u = u.strip()
        if not u or not u.startswith("http"):
            continue
        parsed = urlparse(u)
        path = parsed.path

        if path.endswith(".js") and "/_next/" not in path:
            js_files.append(u)

        if "." in path:
            ext = path.rsplit(".", 1)[-1].lower()
            if ext in ("js","json","xml","yml","env","bak","sql","php","aspx","jsp"):
                file_types.add(ext)

        if re.search(r"/_next/|/static/|/cdn-cgi/|\.(css|png|jpg|ico|svg|woff|woff2|ttf|map|webp)$", path, re.I):
            continue
            
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        endpoints.append(base)

        qp = parse_qs(parsed.query)
        for k in qp:
            params_map.setdefault(k, []).append(u)

        if any(w in u.lower() for w in ["login","signup","register","upload","reset","search"]):
            post_params.setdefault("_suspected_post", []).append(u)

    return EndpointInfo(
        endpoints=sorted(set(endpoints)),
        params={k: sorted(set(v)) for k, v in params_map.items()},
        file_types=sorted(file_types),
        suspected_post_forms=sorted(set(post_params.get("_suspected_post", []))),
        js_files=sorted(set(js_files))
    )

def categorize(endpoints: list) -> dict:
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

def parse_katana_output(url_file: str) -> tuple:
    """Katana output format: URL [status] [method] ..."""
    urls, meta = [], []
    try:
        with open(url_file, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                urls.append(line.split()[0] if " " in line else line)
                meta.append(line)
    except FileNotFoundError:
        pass
    return urls, meta

def parse_whatweb(raw: str) -> dict:
    """Parse whatweb output into tech stack dict"""
    ansi = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    raw_clean = ansi.sub('', raw)
    result = {}
    for line in raw_clean.strip().splitlines():
        if " [" not in line:
            continue
        parts = line.split(" [", 1)
        url = parts[0].strip()
        rest = parts[1].split("]", 1)
        if len(rest) < 2:
            continue
        tags_raw = rest[1].strip().rstrip(",")

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
