import os
import time
import asyncio
import logging

from hb_recon.tools.scanners import (
    run_subfinder_httpx,
    run_katana,
    run_whatweb,
    run_gf_patterns
)
from hb_recon.core.report import build_ai_report, print_summary

logger = logging.getLogger(__name__)

async def run_recon(target: str):
    """Main orchestration flow for hb-recon."""
    work_dir = f"recon_{target}"
    os.makedirs(work_dir, exist_ok=True)
    
    start_time = time.time()
    
    # Phase 1: Subdomain Enum & Live Host Check
    logger.info("Phase 1: Subdomain Enumeration & Live Host Check")
    success = await run_subfinder_httpx(target, work_dir)
    if not success:
        logger.error("Phase 1 failed. Cannot continue.")
        return
        
    # Phase 2: Crawling & Tech Detection (Parallel)
    logger.info("\n[*] Phase 2: WhatWeb + Katana (Parallel)")
    # run_katana writes to urls.txt, run_whatweb parses whatweb output
    katana_task = asyncio.create_task(run_katana(work_dir))
    whatweb_task = asyncio.create_task(run_whatweb(work_dir))
    
    # Wait for both to finish
    await katana_task
    tech_stack = await whatweb_task
    
    # Phase 3: Vulnerability Pattern Matching
    logger.info("\n[*] Phase 3: gf Patterns (XSS/SQLi/IDOR)")
    await run_gf_patterns(work_dir)
    
    # Phase 4: Build AI Report
    logger.info("\n[*] Phase 4: Building AI Report")
    report = build_ai_report(target, work_dir, tech_stack)
    
    total_time = round(time.time() - start_time, 1)
    logger.info(f"\n[√] Total Execution Time: {total_time}s")
    
    # Print final summary to console
    print_summary(report)
