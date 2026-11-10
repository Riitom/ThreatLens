#!/usr/bin/env python3
"""ThreatLens command line: serve the platform, scan a URL, or import a feed."""
from __future__ import annotations

import argparse
import json
import sys

from threatlens import config, engine
from threatlens.intel import IntelStore


def cmd_serve(args) -> int:
    from threatlens.server import create_app

    app = create_app()
    app.run(host=args.host, port=args.port, threaded=True)
    return 0


def cmd_scan(args) -> int:
    store = IntelStore(config.db_path())
    result = engine.scan(args.url, deep=args.deep, authorized=args.authorized, store=store)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    v = result["verdict"]
    print(f"\n{result['url']}")
    print(f"  Verdict : {v['label']} (threat score {v['threat_score']}/100, confidence {v['confidence']})")
    p = result["posture"]
    print(f"  Posture : {p['grade'] or 'n/a'}" + (f" ({p['score']}/100)" if p["score"] is not None else ""))
    print(f"  {v['summary']}\n")
    for f in result["findings"]:
        if f["severity"] == "info":
            continue
        tag = {"threat": "T", "posture": "P", "both": "T+P"}[f["axis"]]
        print(f"  [{f['severity'].upper():8}] ({tag:3}) {f['title']}")
    for n in result["notes"]:
        print(f"  note: {n}")
    return 0


def cmd_import(args) -> int:
    store = IntelStore(config.db_path())
    with open(args.file, encoding="utf-8", errors="replace") as fh:
        n = store.import_feed(fh, args.source, args.category)
    print(f"Imported {n} entries from {args.file} as '{args.source}'")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="threatlens", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the web platform")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=cmd_serve)
    sc = sub.add_parser("scan", help="scan one URL and print the result")
    sc.add_argument("url")
    sc.add_argument("--json", action="store_true")
    sc.add_argument("--deep", action="store_true", help="also check for exposed files (requires --authorized)")
    sc.add_argument("--authorized", action="store_true", help="confirm you own or may test this site")
    sc.set_defaults(fn=cmd_scan)
    im = sub.add_parser("import-feed", help="import a text file of URLs or hosts, one per line")
    im.add_argument("file")
    im.add_argument("--source", default="imported")
    im.add_argument("--category", default="phishing")
    im.set_defaults(fn=cmd_import)
    args = ap.parse_args()
    try:
        return args.fn(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
