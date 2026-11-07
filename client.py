#!/usr/bin/env python3
"""bro-node client: how bro talks to a node.

Connect mode (v2, no IP needed — just the PIN + access key the node
printed on start):

    python3 client.py --pin 123456 --key <access_key> status
    python3 client.py --pin 123456 --key <access_key> exec "command here"
    python3 client.py --pin 123456 --key <access_key> job "long command"
    python3 client.py --pin 123456 --key <access_key> job-status <job_id>
    python3 client.py --pin 123456 --key <access_key> get <remote> <local>
    python3 client.py --pin 123456 --key <access_key> put <local> <remote>

Connect mode reads the node's rendezvous payload from ntfy (topic is
sha256(access_key)), then tries, in order: tunnel_url, Tailscale IPs,
LAN IPs.

Direct mode (old style, still works — v2 nodes also need the PIN):

    python3 client.py <base_url> <access_key> status
    python3 client.py --url <base_url> --pin 123456 --key <access_key> status

The ntfy base can be overridden with BRO_NODE_NTFY_BASE (or --ntfy-base),
e.g. for a self-hosted ntfy.
"""

import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

NTFY_BASE = os.environ.get("BRO_NODE_NTFY_BASE", "https://ntfy.sh").rstrip("/")


def call(base, key, method, path, body=None, pin=None, timeout=300):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method)
    req.add_header("X-Pair-Key", key)
    if pin:
        req.add_header("X-Pin", pin)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def rendezvous_topic(key):
    return "bronode-" + hashlib.sha256(key.encode()).hexdigest()


def fetch_rendezvous(pin, key, ntfy_base=NTFY_BASE):
    """Return the freshest rendezvous payload for this PIN, or None."""
    url = "%s/%s/json?poll=1" % (ntfy_base, rendezvous_topic(key))
    req = urllib.request.Request(url)
    best = None
    with urllib.request.urlopen(req, timeout=20) as r:
        for raw in r:
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except ValueError:
                continue
            msg = event.get("message")
            if not msg:
                continue
            try:
                payload = json.loads(msg)
            except ValueError:
                continue
            if str(payload.get("pin")) != str(pin):
                continue
            if best is None or payload.get("ts", 0) >= best.get("ts", 0):
                best = payload
    return best


def _hostport(ip, port):
    if ":" in ip and not ip.startswith("["):
        ip = "[%s]" % ip  # IPv6 literal needs brackets in a URL
    return "http://%s:%d" % (ip, port)


def candidate_bases(payload):
    bases = []
    if payload.get("tunnel_url"):
        bases.append(payload["tunnel_url"])
    port = payload.get("port", 8899)
    for ip in payload.get("tailscale_ips") or []:
        bases.append(_hostport(ip, port))
    for ip in payload.get("lan_ips") or []:
        bases.append(_hostport(ip, port))
    return bases


def discover(pin, key, ntfy_base=NTFY_BASE):
    """Find a reachable base URL for the node using only PIN + key."""
    payload = fetch_rendezvous(pin, key, ntfy_base)
    if not payload:
        raise RuntimeError("no rendezvous payload found for that PIN/key (is the node running?)")
    last_err = None
    for base in candidate_bases(payload):
        try:
            call(base, key, "GET", "/api/status", pin=pin, timeout=6)
            return base
        except Exception as e:
            last_err = e
    raise RuntimeError("node announced %s but none were reachable (last error: %s)"
                       % (candidate_bases(payload), last_err))


def run_action(base, key, pin, action, rest):
    if action == "status":
        print(call(base, key, "GET", "/api/status", pin=pin).decode())
    elif action == "exec":
        out = json.loads(call(base, key, "POST", "/api/exec", {"cmd": rest[0]}, pin=pin))
        sys.stdout.write(out.get("stdout", ""))
        sys.stderr.write(out.get("stderr", ""))
        return out.get("exit", 1)
    elif action == "job":
        print(call(base, key, "POST", "/api/job", {"cmd": rest[0]}, pin=pin).decode())
    elif action == "job-status":
        print(call(base, key, "GET", "/api/job/" + rest[0], pin=pin).decode())
    elif action == "get":
        data = call(base, key, "GET", "/api/file?path=" + urllib.request.quote(rest[0]), pin=pin)
        with open(rest[1], "wb") as f:
            f.write(data)
        print("wrote", rest[1], len(data), "bytes")
    elif action == "put":
        with open(rest[0], "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        print(call(base, key, "POST", "/api/file", {"path": rest[1], "content_b64": b64}, pin=pin).decode())
    else:
        print("unknown action:", action)
        return 1
    return 0


def main():
    argv = sys.argv[1:]
    pin = os.environ.get("BRO_NODE_PIN", "")
    key = ""
    url = ""
    ntfy_base = NTFY_BASE
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--pin":
            pin = argv[i + 1]; i += 2
        elif a == "--key":
            key = argv[i + 1]; i += 2
        elif a == "--url":
            url = argv[i + 1]; i += 2
        elif a == "--ntfy-base":
            ntfy_base = argv[i + 1].rstrip("/"); i += 2
        else:
            positional.append(a); i += 1

    # Old positional form: client.py <base_url> <key> <action> [args...]
    if not url and not key and len(positional) >= 3 and positional[0].startswith("http"):
        url, key = positional[0], positional[1]
        positional = positional[2:]

    if not positional:
        print(__doc__)
        return 1
    action, rest = positional[0], positional[1:]

    if not key:
        print("error: --key <access_key> is required")
        return 1

    if not url:
        try:
            url = discover(pin, key, ntfy_base)
        except Exception as e:
            print("connect failed:", e, file=sys.stderr)
            return 2
        print("connected via", url, file=sys.stderr)

    try:
        return run_action(url, key, pin or None, action, rest)
    except urllib.error.HTTPError as e:
        print("HTTP", e.code, e.read().decode("utf-8", "replace"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
