import os
from hb_recon.config import Config
from hb_recon.tools.executor import run_async_command
from hb_recon.core.parser import parse_whatweb

async def run_subfinder_httpx(target: str, work_dir: str) -> bool:
    """Run subfinder piped into httpx-toolkit"""
    cmd = (
        f"{Config.SUBFINDER} -d {target} -s hackertarget,waybackarchive -silent | "
        f"tee {work_dir}/subdomains.txt | "
        f"{Config.HTTPX} -mc 200,301,403 -silent > {work_dir}/alive.txt"
    )
    return await run_async_command(cmd, "Subfinder + Httpx", Config.TIMEOUT_SECONDS)

async def run_katana(work_dir: str) -> bool:
    """Run katana web crawler"""
    cmd = f"{Config.KATANA} -list {work_dir}/alive.txt -d {Config.KATANA_DEPTH} -c {Config.KATANA_CONCURRENCY} -silent > {work_dir}/urls.txt"
    return await run_async_command(cmd, "Katana (crawl)", Config.TIMEOUT_SECONDS)

async def run_whatweb(work_dir: str) -> dict:
    """Run whatweb for tech stack detection"""
    alive_file = f"{work_dir}/alive.txt"
    if not os.path.exists(alive_file):
        return {}
        
    with open(alive_file, "r") as f:
        hosts = [l.strip() for l in f if l.strip().startswith("http")]
        
    if not hosts:
        return {}
        
    outfile = f"{work_dir}/whatweb.txt"
    hosts_str = " ".join(hosts)
    cmd = f"{Config.WHATWEB} --color=never --no-errors {hosts_str}"
    
    # Run whatweb
    success = await run_async_command(cmd, f"WhatWeb ({len(hosts)} hosts)", Config.TIMEOUT_SECONDS, outfile=outfile)
    
    if success and os.path.exists(outfile):
        with open(outfile, "r") as f:
            return parse_whatweb(f.read())
    return {}

async def run_gf_patterns(work_dir: str) -> bool:
    """Run gf to find vulnerability patterns"""
    if not os.path.exists(f"{work_dir}/urls.txt"):
        return False
        
    cmd = (
        f"cat {work_dir}/urls.txt | {Config.GF} xss > {work_dir}/xss.txt && "
        f"cat {work_dir}/urls.txt | {Config.GF} sqli > {work_dir}/sqli.txt && "
        f"cat {work_dir}/urls.txt | {Config.GF} idor > {work_dir}/idor.txt"
    )
    return await run_async_command(cmd, "gf (XSS/SQLi/IDOR patterns)", Config.TIMEOUT_SECONDS)
