import argparse
import asyncio
import re
import sys
from hb_recon.config import IS_WINDOWS, setup_logging
from hb_recon.core.orchestrator import run_recon

def main():
    print("=" * 55)
    print("  Auto Recon -> AI Ready (Async)")
    print("=" * 55)

    if IS_WINDOWS:
        print('[!] Error: hb-recon requires Linux/WSL environment or Docker')
        print('[!] Tools required: subfinder, httpx, katana, gf, whatweb')
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Automated reconnaissance workflow with AI-ready report generation.")
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)", required=False)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()

    setup_logging(debug=args.debug)

    target = args.domain
    if not target:
        try:
            target = input("\n[>] Domain: ").strip()
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)
            
    if not target:
        return

    # Clean input: strip https://, http://, trailing /
    target = re.sub(r'^https?://', '', target).rstrip('/')

    try:
        asyncio.run(run_recon(target))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)

if __name__ == "__main__":
    main()
