"""Run the two-agent attack demo against a running AuthorityGuard and print the trace.

python scripts/run_demo.py                                   # http://127.0.0.1:8000
python scripts/run_demo.py --url https://authorityguard.onrender.com
"""

import argparse
import sys

import httpx

COLORS = {"allow": "\033[32m", "deny": "\033[31m", "approval_required": "\033[33m"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    args = ap.parse_args()

    r = httpx.post(f"{args.url.rstrip('/')}/v1/demo/run", json={"auto_approve": True}, timeout=120)
    r.raise_for_status()
    run = r.json()
    print(f"run {run['run_id']}  task {run['task_id']}  status {run['status']}\n")
    for i, s in enumerate(run["steps"], 1):
        d = s.get("decision") or "info"
        color = COLORS.get(d, "\033[90m")
        print(
            f"{i:>2}. {s['agent']:<22} {s['title'][:55]:<55} {color}{d:<18}\033[0m "
            f"{s.get('reason_code') or ''}"
        )
    blocked = sum(s.get("decision") == "deny" for s in run["steps"])
    print(f"\n{blocked} unauthorized actions blocked. Dashboard: {args.url.rstrip('/')}/dashboard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
