#!/usr/bin/env python3
"""bro-node: a tiny remote-hands server (v2: PIN + fresh access key).

Run this on any machine (Linux PC, or Android via Termux) and bro can
connect and work: run commands, move files, use the machine as extra
processing power. Standard library only, no installs beyond Python 3.

    python3 server.py [--port 8899] [--name mypc]

No IP address needed. On every start the node generates:
  - a 6-digit PIN
  - a FRESH random ACCESS KEY (different every start; the previous
    start's key stops working the moment the node restarts)

Jay sends bro just the PIN + ACCESS KEY. The node publishes how to
reach it (LAN IPs, Tailscale IPs, and a Cloudflare tunnel URL when
cloudflared is installed) to an ntfy.sh topic derived from
sha256(access_key), so bro can find the node from the key alone.

State lives in ~/.bro-node/ (job logs only; no key is stored anymore).
"""

import argparse
import base64
import hashlib
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
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME_DIR = os.environ.get("BRO_NODE_HOME", os.path.expanduser("~/.bro-node"))
JOBS_DIR = os.path.join(HOME_DIR, "jobs")
MAX_OUT = 256 * 1024
NTFY_BASE = os.environ.get("BRO_NODE_NTFY_BASE", "https://ntfy.sh").rstrip("/")

# --- session credentials: generated fresh on EVERY start, never stored ---
PIN = "%06d" % (secrets.randbelow(900000) + 100000)
ACCESS_KEY = secrets.token_urlsafe(24)


def rendezvous_topic():
    """Unguessable ntfy topic derived from the session access key."""
    return "bronode-" + hashlib.sha256(ACCESS_KEY.encode()).hexdigest()


# Small catastrophic-command guard. This is a speed bump, not a sandbox:
# anyone with the PIN + access key is trusted, but a typo should not be
# able to wipe the machine.
GUARDS = [
    re.compile(r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\s*$"),
    re.compile(r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\s"),
    re.compile(r"\bmkfs(\.|\s)"),
    re.compile(r"\bdd\b[^|]*\bof=/dev/"),
    re.compile(r":\(\)\s*\{"),
    re.compile(r"\b(shutdown|poweroff|halt)\b"),
    re.compile(r">\s*/dev/(sd|nvme|mmcblk)"),
]

JOBS = {}
JOBS_LOCK = threading.Lock()

# Set by the tunnel thread when cloudflared gives us a public URL.
TUNNEL_URL = None
TUNNEL_LOCK = threading.Lock()


def get_tunnel_url():
    with TUNNEL_LOCK:
        return TUNNEL_URL


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


def all_ips():
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


def split_ips():
    """(lan_ips, tailscale_ips): Tailscale addresses live in 100.64.0.0/10.

    BRO_NODE_ADVERTISE_IPS (comma-separated) overrides auto-detection,
    for multi-homed machines or containers whose hostname -I addresses
    are not the ones peers should dial.
    """
    override = os.environ.get("BRO_NODE_ADVERTISE_IPS", "").strip()
    ips = [s.strip() for s in override.split(",") if s.strip()] if override else all_ips()
    lan, ts = [], []
    for ip in ips:
        parts = ip.split(".")
        is_ts = False
        if len(parts) == 4 and parts[0] == "100":
            try:
                is_ts = 64 <= int(parts[1]) <= 127
            except ValueError:
                is_ts = False
        (ts if is_ts else lan).append(ip)
    return lan, ts


def lan_ips():
    lan, ts = split_ips()
    return lan + ts


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
    lan, ts = split_ips()
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
        "ips": lan + ts,
        "lan_ips": lan,
        "tailscale_ips": ts,
        "tunnel_url": get_tunnel_url(),
        "port": port,
        "uptime_s": None,
    }


# --- rendezvous: publish reachability to ntfy so bro needs no IP ---


def rendezvous_payload(port, name):
    lan, ts = split_ips()
    return {
        "pin": PIN,
        "name": name,
        "port": port,
        "lan_ips": lan,
        "tailscale_ips": ts,
        "tunnel_url": get_tunnel_url(),
        "ts": int(time.time()),
    }


def publish_rendezvous(port, name):
    """POST the payload to the ntfy topic. Returns True on success."""
    url = NTFY_BASE + "/" + rendezvous_topic()
    body = json.dumps(rendezvous_payload(port, name)).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "text/plain; charset=utf-8")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 300
    except Exception as e:
        print("[rendezvous] publish failed (%s); will retry" % e, flush=True)
        return False


def rendezvous_loop(port, name):
    while True:
        publish_rendezvous(port, name)
        time.sleep(60)


# --- optional Cloudflare quick tunnel ---


def tunnel_loop(port, name):
    global TUNNEL_URL
    exe = shutil.which("cloudflared")
    if not exe:
        return
    try:
        p = subprocess.Popen(
            [exe, "tunnel", "--url", "http://127.0.0.1:%d" % port],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except Exception as e:
        print("[tunnel] cloudflared failed to start: %s" % e, flush=True)
        return
    pat = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
    for line in p.stdout:
        m = pat.search(line)
        if m:
            with TUNNEL_LOCK:
                TUNNEL_URL = m.group(0)
            print("[tunnel] public URL: %s" % TUNNEL_URL, flush=True)
            publish_rendezvous(port, name)
            break


CONSOLE = """<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>bro-node</title>
<body style="background:#0a0b0d;color:#e8e8e8;font-family:monospace;padding:24px">
<h2>bro-node is running</h2>
<p>This machine is available to bro with this session's PIN + access key.</p>
<pre id="s">loading status...</pre>
<script>
var q = new URLSearchParams(location.search);
fetch('/api/status', {headers: {'X-Pair-Key': q.get('key') || '', 'X-Pin': q.get('pin') || ''}})
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
        # BOTH required: X-Pin header must equal the session PIN and
        # X-Pair-Key (or ?key=) must equal the current session access key.
        from urllib.parse import urlparse, parse_qs

        q = parse_qs(urlparse(self.path).query)
        pin = self.headers.get("X-Pin", "") or q.get("pin", [""])[0]
        key = self.headers.get("X-Pair-Key", "") or q.get("key", [""])[0]
        return secrets.compare_digest(pin, PIN) and secrets.compare_digest(key, ACCESS_KEY)

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
            return self.send_json(401, {"error": "valid PIN + access key required"})
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
            return self.send_json(401, {"error": "valid PIN + access key required"})
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
    os.makedirs(HOME_DIR, exist_ok=True)
    Handler.port = args.port
    Handler.name = args.name
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)

    threading.Thread(target=tunnel_loop, args=(args.port, args.name), daemon=True).start()
    threading.Thread(target=rendezvous_loop, args=(args.port, args.name), daemon=True).start()

    print("=" * 56, flush=True)
    print("  bro-node is running: %s" % args.name, flush=True)
    print("", flush=True)
    print("  PIN:        %s" % PIN, flush=True)
    print("  ACCESS KEY: %s" % ACCESS_KEY, flush=True)
    print("", flush=True)
    print("  Tell bro: PIN %s + ACCESS KEY (above)" % PIN, flush=True)
    print("  The access key is new every start. Keep this terminal open.", flush=True)
    print("=" * 56, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
