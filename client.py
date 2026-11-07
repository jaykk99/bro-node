#!/usr/bin/env python3
"""bro-node client: how bro talks to a node.

Usage:
    python3 client.py <base_url> <pairing_key> status
    python3 client.py <base_url> <pairing_key> exec "command here"
    python3 client.py <base_url> <pairing_key> job "long command"
    python3 client.py <base_url> <pairing_key> job-status <job_id>
    python3 client.py <base_url> <pairing_key> get <remote_path> <local_path>
    python3 client.py <base_url> <pairing_key> put <local_path> <remote_path>
"""

import base64
import json
import sys
import urllib.request


def call(base, key, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method)
    req.add_header("X-Pair-Key", key)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 1
    base, key, action = sys.argv[1], sys.argv[2], sys.argv[3]
    if action == "status":
        print(call(base, key, "GET", "/api/status").decode())
    elif action == "exec":
        out = json.loads(call(base, key, "POST", "/api/exec", {"cmd": sys.argv[4]}))
        sys.stdout.write(out.get("stdout", ""))
        sys.stderr.write(out.get("stderr", ""))
        return out.get("exit", 1)
    elif action == "job":
        print(call(base, key, "POST", "/api/job", {"cmd": sys.argv[4]}).decode())
    elif action == "job-status":
        print(call(base, key, "GET", "/api/job/" + sys.argv[4]).decode())
    elif action == "get":
        data = call(base, key, "GET", "/api/file?path=" + urllib.request.quote(sys.argv[4]))
        with open(sys.argv[5], "wb") as f:
            f.write(data)
        print("wrote", sys.argv[5], len(data), "bytes")
    elif action == "put":
        with open(sys.argv[4], "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        print(call(base, key, "POST", "/api/file", {"path": sys.argv[5], "content_b64": b64}).decode())
    else:
        print("unknown action:", action)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
