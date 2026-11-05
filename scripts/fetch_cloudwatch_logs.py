#!/usr/bin/env python3
"""Fetch the last N minutes from several CloudWatch log groups, redact, and bundle for the LLM.

Prints one JSON document:
  {"sources": {"<name>": {"group": ..., "lines": N, "error": null}}, "bundle": "<text>"}
Credentials come from the standard AWS environment variables (injected by the AAP credential).
"""
import argparse
import datetime as dt
import json
import re
import sys
import time

import boto3
from botocore.exceptions import BotoCoreError, ClientError

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SECRET = re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key)=\S+")
MAX_BUNDLE_CHARS = 100_000


def redact(line):
    line = IPV4.sub(lambda m: m.group(0) if m.group(0).startswith("127.") else "x.x.x.x", line)
    return SECRET.sub(lambda m: m.group(1) + "=REDACTED", line)


def fetch_group(client, group, start_ms, end_ms, max_lines):
    events = []
    paginator = client.get_paginator("filter_log_events")
    for page in paginator.paginate(
        logGroupName=group,
        startTime=start_ms,
        endTime=end_ms,
        PaginationConfig={"MaxItems": 5000},
    ):
        events.extend(page.get("events", []))
    events.sort(key=lambda e: e["timestamp"])
    return events[-max_lines:]


def collect(region, minutes, max_lines, sources):
    client = boto3.client("logs", region_name=region)
    end_ms = int(time.time() * 1000)
    start_ms = end_ms - minutes * 60 * 1000
    result = {"sources": {}, "bundle": ""}
    parts = []
    for src in sources:
        name, group = src["name"], src["group"]
        try:
            events = fetch_group(client, group, start_ms, end_ms, max_lines)
            error = None
        except (ClientError, BotoCoreError) as exc:
            events, error = [], str(exc)
        lines = []
        for e in events:
            ts = dt.datetime.fromtimestamp(e["timestamp"] / 1000, dt.timezone.utc).strftime("%H:%M:%S")
            lines.append(f"{ts} {redact(e['message'].rstrip())}")
        result["sources"][name] = {"group": group, "lines": len(lines), "error": error}
        body = "\n".join(lines) if lines else "(no events in this window)"
        parts.append(f"===== SOURCE: {name} ({group}) =====\n{body}")
    bundle = "\n\n".join(parts)
    if len(bundle) > MAX_BUNDLE_CHARS:
        bundle = bundle[-MAX_BUNDLE_CHARS:]
    result["bundle"] = bundle
    return result


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", required=True)
    ap.add_argument("--minutes", type=int, default=15)
    ap.add_argument("--max-lines", type=int, default=120)
    ap.add_argument("--sources", required=True, help='JSON list: [{"name":..,"group":..}]')
    args = ap.parse_args(argv)
    sources = json.loads(args.sources)
    print(json.dumps(collect(args.region, args.minutes, args.max_lines, sources)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
