#!/usr/bin/env python3
"""bro-node: a tiny remote-hands server.

Run this on any machine (Linux PC, or Android via Termux) and bro can
connect with the pairing key to run commands, move files, and use the
machine as extra processing power. Standard library only, no installs
beyond Python 3 itself.

Usage:
    python3 server.py [--port 8899] [--name mypc]

State lives in ~/.bro-node/ (pairing key, job logs). The pairing key is
printed on start. Whoever holds the key controls the machine, so only
share it with bro, and do not port-forward this to the open internet
(use Tailscale for remote access instead).
"""

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME_DIR = os.environ.get("BRO_NODE_HOME", os.path.expanduser("~/.bro-node"))
KEY_FILE = os.path.join(HOME_DIR, "pairing-key")
JOBS_DIR = os.path.join(HOME_DIR, "jobs")
MAX_OUT = 256 * 1024

# Small catastrophic-command guard. This is a speed bump, not a sandbox:
# anyone with the pairing key is trusted, but a typo should not be able
# to wipe the machine.
GUARDS = [
    re.compile(r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\s*$"),
    re.compile(r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\s"),
    re.compile(r"\bmkfs(\.|\s)"),
    re.compile(r"\bdd\b[^|]*\bof=/dev/"),
    re.compile(r":\(\)\s*\{"),
    re.compile(r"\b(shutdown|poweroff|halt)\b"),
    re.compile(r">\s*/dev/(sd|nvme|mmcblk)"),
]


def load_key():
    os.makedirs(HOME_DIR, exist_ok=True)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            return f.read().strip()
    key = secrets.token_urlsafe(24)
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key + "\n")
    return key


PAIR_KEY = load_key()
JOBS = {}
JOBS_LOCK = threading.Lock()


def shell_prefix():
    bash = shutil.which("bash")
    if bash:
        return [bash, "-lc"]
    return ["sh", "-c"]


def guarded(cmd):
    return any(g.search(cmd) for g in GUARDS)


def run_cmd(cmd, timeout_s, cwd=None):
    if guarded(cmd):
        return {"exit": 126, "stdout": "", "stderr": "blocked by safety guard", "ms": 0}
    start = time.time()
    try:
        p = subprocess.run(
            shell_prefix() + [cmd],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=cwd or os.path.expanduser("~"),
        )
        return {
            "exit": p.returncode,
            "stdout": p.stdout[-MAX_OUT:],
            "stderr": p.stderr[-MAX_OUT:],
            "ms": int((time.time() - start) * 1000),
        }
    except subprocess.TimeoutExpired as e:
        return {
            "exit": 124,
            "stdout": (e.stdout or "")[-MAX_OUT:] if isinstance(e.stdout, str) else "",
            "stderr": "timed out after %ss" % timeout_s,
            "ms": int((time.time() - start) * 1000),
        }


def start_job(cmd):
    jid = uuid.uuid4().hex[:12]
    os.makedirs(JOBS_DIR, exist_ok=True)
    log_path = os.path.join(JOBS_DIR, jid + ".log")

    def work():
        with open(log_path, "w") as log:
            if guarded(cmd):
                log.write("blocked by safety guard\n")
                code = 126
            else:
                p = subprocess.Popen(
                    shell_prefix() + [cmd],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    cwd=os.path.expanduser("~"),
                )
                code = p.wait()
        with JOBS_LOCK:
            JOBS[jid]["status"] = "done"
            JOBS[jid]["exit"] = code
            JOBS[jid]["ended"] = time.time()

    with JOBS_LOCK:
        JOBS[jid] = {"cmd": cmd, "status": "running", "started": time.time(), "log": log_path}
    threading.Thread(target=work, daemon=True).start()
    return jid


def job_info(jid):
    with JOBS_LOCK:
        j = JOBS.get(jid)
        if not j:
            return None
        info = dict(j)
    tail = ""
    try:
        with open(info["log"], "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 64 * 1024))
            tail = f.read().decode("utf-8", "replace")
    except OSError:
        pass
    info["tail"] = tail
    del info["log"]
    return info


def battery():
    exe = shutil.which("termux-battery-status")
    if exe:
        try:
            out = subprocess.run([exe], capture_output=True, text=True, timeout=5)
            return json.loads(out.stdout)
        except Exception:
            pass
    base = "/sys/class/power_supply"
    try:
        for name in os.listdir(base):
            cap = os.path.join(base, name, "capacity")
            if os.path.exists(cap):
                with open(cap) as f:
                    return {"percentage": int(f.read().strip())}
    except OSError:
        pass
    return None


def lan_ips():
    ips = []
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        ips = out.stdout.split()
    except Exception:
        pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips = [s.getsockname()[0]]
            s.close()
        except OSError:
            pass
    return ips


def status(port, name):
    mem_total = mem_avail = None
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1]) // 1024
                elif line.startswith("MemAvailable:"):
                    mem_avail = int(line.split()[1]) // 1024
    except OSError:
        pass
    disk = shutil.disk_usage(os.path.expanduser("~"))
    return {
        "node": name,
        "hostname": socket.gethostname(),
        "os": sys.platform,
        "python": sys.version.split()[0],
        "cores": os.cpu_count(),
        "load": os.getloadavg(),
        "mem_total_mb": mem_total,
        "mem_avail_mb": mem_avail,
        "disk_free_gb": round(disk.free / 1e9, 1),
        "disk_total_gb": round(disk.total / 1e9, 1),
        "battery": battery(),
        "ips": lan_ips(),
        "port": port,
        "uptime_s": None,
    }


CONSOLE = """<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>bro-node</title>
<body style="background:#0a0b0d;color:#e8e8e8;font-family:monospace;padding:24px">
<h2>bro-node is running</h2>
<p>This machine is available to bro with its pairing key.</p>
<pre id="s">loading status...</pre>
<script>
fetch('/api/status', {headers: {'X-Pair-Key': new URLSearchParams(location.search).get('key') || ''}})
  .then(r => r.json()).then(j => document.getElementById('s').textContent = JSON.stringify(j, null, 2))
  .catch(e => document.getElementById('s').textContent = 'status failed: ' + e);
</script>
</body>
"""


class Handler(BaseHTTPRequestHandler):
    port = 8899
    name = socket.gethostname()

    def log_message(self, *args):
        pass

    def authed(self):
        key = self.headers.get("X-Pair-Key", "")
        if not key:
            from urllib.parse import urlparse, parse_qs

            key = parse_qs(urlparse(self.path).query).get("key", [""])[0]
        return secrets.compare_digest(key, PAIR_KEY)

    def send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get("Content-Length", 0))
        if n <= 0:
            return {}
        return json.loads(self.rfile.read(n).decode("utf-8"))

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs

        u = urlparse(self.path)
        if u.path == "/":
            body = CONSOLE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not self.authed():
            return self.send_json(401, {"error": "pairing key required"})
        if u.path == "/api/status":
            return self.send_json(200, status(self.port, self.name))
        if u.path.startswith("/api/job/"):
            info = job_info(u.path.split("/")[-1])
            if info is None:
                return self.send_json(404, {"error": "no such job"})
            return self.send_json(200, info)
        if u.path == "/api/file":
            path = parse_qs(u.query).get("path", [""])[0]
            ap = os.path.abspath(os.path.expanduser(path))
            if not os.path.isfile(ap):
                return self.send_json(404, {"error": "no such file"})
            with open(ap, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        return self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if not self.authed():
            return self.send_json(401, {"error": "pairing key required"})
        from urllib.parse import urlparse

        u = urlparse(self.path)
        try:
            body = self.read_json()
        except Exception:
            return self.send_json(400, {"error": "bad json"})
        if u.path == "/api/exec":
            cmd = body.get("cmd", "")
            if not cmd:
                return self.send_json(400, {"error": "cmd required"})
            return self.send_json(200, run_cmd(cmd, int(body.get("timeout_s", 120)), body.get("cwd")))
        if u.path == "/api/job":
            cmd = body.get("cmd", "")
            if not cmd:
                return self.send_json(400, {"error": "cmd required"})
            return self.send_json(200, {"job": start_job(cmd)})
        if u.path == "/api/file":
            path = body.get("path", "")
            if not path or "content_b64" not in body:
                return self.send_json(400, {"error": "path and content_b64 required"})
            ap = os.path.abspath(os.path.expanduser(path))
            os.makedirs(os.path.dirname(ap), exist_ok=True)
            with open(ap, "wb") as f:
                f.write(base64.b64decode(body["content_b64"]))
            return self.send_json(200, {"written": ap})
        return self.send_json(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("BRO_NODE_PORT", "8899")))
    ap.add_argument("--name", default=os.environ.get("BRO_NODE_NAME", socket.gethostname()))
    args = ap.parse_args()
    Handler.port = args.port
    Handler.name = args.name
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print("bro-node '%s' listening on port %d" % (args.name, args.port))
    print("pairing key: %s" % PAIR_KEY)
    for ip in lan_ips() or ["127.0.0.1"]:
        print("  http://%s:%d" % (ip, args.port))
    print("CONNECT LINE for bro: bro-node http://<this-machine-ip>:%d key %s" % (args.port, PAIR_KEY))
    print("Keep this terminal open. Ctrl-C stops the node.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
