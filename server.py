#!/usr/bin/env python3
"""bro-node: a tiny remote-hands server (v2.2: PIN + fresh access key).

Run this on any machine (Linux PC, or Android via Termux) and bro can
connect and work: run commands, move files, use the machine as extra
processing power. Standard library only, no installs beyond Python 3.

Old gear is welcome (v2.2): the floor is Python 3.6, so old Termux /
old Android and old Linux distros can run it. When a device has no
usable CA store (the classic Termux CERTIFICATE_VERIFY_FAILED), TLS
verification falls back instead of failing outright, plain (non-TLS)
broker transports are in the rendezvous rotation, and when
cloudflared is unavailable or cannot run, an ssh reverse tunnel
(localhost.run) is tried instead.

    python3 server.py [--port 8899] [--name mypc]

No IP address needed. On every start the node generates:
  - a 6-digit PIN
  - a FRESH random ACCESS KEY (different every start; the previous
    start's key stops working the moment the node restarts)

Jay sends bro just the PIN + ACCESS KEY. The node publishes how to
reach it (LAN IPs, Tailscale IPs, and a Cloudflare tunnel URL when
cloudflared is installed) as a retained MQTT message on public
brokers (topic bronode/<sha256(access_key)>) and, secondarily, to an
ntfy.sh topic derived the same way, so bro can find the node from
the key alone.

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
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    from http.server import ThreadingHTTPServer
except ImportError:  # Python 3.6 has no ThreadingHTTPServer
    import socketserver

    class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True

HOME_DIR = os.environ.get("BRO_NODE_HOME", os.path.expanduser("~/.bro-node"))
JOBS_DIR = os.path.join(HOME_DIR, "jobs")
MAX_OUT = 256 * 1024
NTFY_BASE = os.environ.get("BRO_NODE_NTFY_BASE", "https://ntfy.sh").rstrip("/")

# --- session credentials: generated fresh on EVERY start, never stored ---
PIN = "%06d" % (secrets.randbelow(900000) + 100000)
ACCESS_KEY = secrets.token_urlsafe(24)
SESSION_ID = uuid.uuid4().hex


def rendezvous_topic():
    """Unguessable ntfy topic derived from the session access key."""
    return "bronode-" + hashlib.sha256(ACCESS_KEY.encode()).hexdigest()


def mqtt_rendezvous_topic():
    """MQTT topic derived from the session access key (same hash as ntfy)."""
    return "bronode/" + hashlib.sha256(ACCESS_KEY.encode()).hexdigest()


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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
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
            out = subprocess.run(
                [exe],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5,
            )
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
        out = subprocess.run(
            ["hostname", "-I"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=5,
        )
        ips = out.stdout.split()
    except Exception:
        pass
    if not ips:
        # No `hostname` here (old Termux/Android): try iproute2.
        try:
            out = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "scope", "global"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5,
            )
            for line in out.stdout.splitlines():
                parts = line.split()
                if "inet" in parts:
                    ips.append(parts[parts.index("inet") + 1].split("/")[0])
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
    try:
        load = list(os.getloadavg())
    except Exception:
        load = None
    return {
        "node": name,
        "hostname": socket.gethostname(),
        "os": sys.platform,
        "python": sys.version.split()[0],
        "cores": os.cpu_count(),
        "load": load,
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


# --- rendezvous: publish reachability so bro needs no IP ---
#
# Primary: MQTT retained message on public brokers (topic derived from
# the access key, so only key holders can find the node). Secondary:
# ntfy.sh (kept from v2). Both are best-effort: failures are logged and
# retried on the next 60s cycle, never fatal.


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
        "session_id": SESSION_ID,
    }


def publish_ntfy(payload):
    """POST the payload to the ntfy topic. Returns True on success."""
    url = NTFY_BASE + "/" + rendezvous_topic()
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "text/plain; charset=utf-8")
    contexts = [make_ssl_context()]
    if hasattr(ssl, "_create_unverified_context"):
        contexts.append("unverified")
    for ctx in contexts:
        try:
            if ctx == "unverified":
                if not TLS_DEGRADED[0]:
                    TLS_DEGRADED[0] = True
                    print(
                        "[tls] ntfy publish retrying without certificate "
                        "verification (old/missing CA store)",
                        flush=True,
                    )
                ctx = ssl._create_unverified_context()
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
            with opener.open(req, timeout=10) as r:
                return 200 <= r.getcode() < 300
        except Exception as e:
            if _cert_verify_failed(e):
                continue
            print("[rendezvous] publish failed (%s); will retry" % e, flush=True)
            return False
    print("[rendezvous] publish failed (TLS on this device); will retry", flush=True)
    return False


# --- minimal MQTT 3.1.1 client (stdlib only) ---
#
# Transports, tried in order per broker:
#   1. WebSocket (wss) with the vendored stdlib ws client below. Works
#      through HTTP proxies: when http_proxy/https_proxy is set, the
#      wss connection is opened through an HTTP CONNECT tunnel.
#   2. Plain TCP to the broker's mqtt (1883) / mqtts (8883) ports.
#
# Sockets are kept in blocking mode with kernel SO_RCVTIMEO timeouts:
# Python's timeout-mode (nonblocking + select) sockets stall behind
# some egress proxies on non-443 ports; blocking + RCVTIMEO does not.

MQTT_BROKERS = [
    {
        "name": "emqx",
        "wss": [("broker.emqx.io", 8084, "/mqtt")],
        "ws": [("broker.emqx.io", 8083, "/mqtt")],
        "tcp": [("broker.emqx.io", 1883, False), ("broker.emqx.io", 8883, True)],
    },
    {
        "name": "mosquitto",
        "wss": [("test.mosquitto.org", 8081, "/mqtt"), ("test.mosquitto.org", 8081, "/")],
        "ws": [("test.mosquitto.org", 8080, "/mqtt")],
        "tcp": [("test.mosquitto.org", 1883, False), ("test.mosquitto.org", 8883, True)],
    },
]


TLS_DEGRADED = [False]  # True once we fall back to unverified TLS


def _ca_bundle():
    """Locate a CA bundle file, including Termux and old-distro paths."""
    env = os.environ.get("SSL_CERT_FILE")
    if env and os.path.exists(env):
        return env
    prefix = os.environ.get("PREFIX", "")
    candidates = []
    if prefix:
        candidates.append(os.path.join(prefix, "etc/tls/cert.pem"))
        candidates.append(os.path.join(prefix, "etc/ssl/certs/ca-certificates.crt"))
    candidates.extend(
        [
            "/etc/tls/cert.pem",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-bundle.crt",
            os.path.expanduser("~/.termux/ssl/cert.pem"),
        ]
    )
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


def make_ssl_context():
    """A verified TLS context using the best CA bundle we can find."""
    bundle = _ca_bundle()
    try:
        if bundle:
            return ssl.create_default_context(cafile=bundle)
        return ssl.create_default_context()
    except Exception:
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx


def _cert_verify_failed(e):
    if isinstance(e, getattr(ssl, "CertificateError", ())):
        return True
    msg = str(e).lower()
    needles = (
        "certificate_verify_failed",
        "certificate verify failed",
        "self-signed certificate",
        "self signed certificate",
        "unable to get local issuer",
        "certificate has expired",
        "doesn't match",
        "not trusted",
    )
    return any(n in msg for n in needles)


def _sock_timeouts(s, sec):
    try:
        s.settimeout(None)
    except Exception:
        pass
    tv = struct.pack("ll", int(sec), 0)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, tv)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, tv)
    except OSError:
        try:
            s.settimeout(sec)
        except Exception:
            pass


def _proxy_url():
    for var in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        u = os.environ.get(var)
        if u:
            from urllib.parse import urlparse

            p = urlparse(u if "://" in u else "http://" + u)
            if p.hostname:
                return p
    return None


def _no_proxy(host):
    raw = os.environ.get("no_proxy") or os.environ.get("NO_PROXY") or ""
    for item in raw.split(","):
        item = item.strip().lstrip(".")
        if item and (host == item or host.endswith("." + item)):
            return True
    return False


def _open_plain(host, port, timeout=15):
    """Plain TCP (optionally via proxy CONNECT). Blocking mode."""
    proxy = None if _no_proxy(host) else _proxy_url()
    if proxy:
        s = socket.create_connection((proxy.hostname, proxy.port or 3128), timeout=timeout)
        _sock_timeouts(s, timeout)
        auth = ""
        if proxy.username:
            cred = base64.b64encode(
                ("%s:%s" % (proxy.username, proxy.password or "")).encode()
            ).decode()
            auth = "Proxy-Authorization: Basic %s\r\n" % cred
        req = (
            "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%sProxy-Connection: Keep-Alive\r\n\r\n"
            % (host, port, host, port, auth)
        )
        s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                raise OSError("proxy closed during CONNECT")
            buf += chunk
            if len(buf) > 65536:
                raise OSError("proxy CONNECT response too large")
        status = buf.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        if " 200" not in status:
            raise OSError("proxy CONNECT failed: %s" % status)
        return s
    s = socket.create_connection((host, port), timeout=timeout)
    _sock_timeouts(s, timeout)
    return s


def _open_connection(host, port, use_tls, timeout=15):
    """TCP + optional TLS. Blocking mode.

    Old Android/Termux and old Linux installs often have no usable CA
    store, so certificate verification fails outright. When that (and
    only that) happens, reconnect once and retry without verification:
    a found node beats no node, and the session access key itself never
    travels over these rendezvous connections."""
    s = _open_plain(host, port, timeout)
    if not use_tls:
        return s
    try:
        s2 = make_ssl_context().wrap_socket(s, server_hostname=host)
        _sock_timeouts(s2, timeout)
        return s2
    except ssl.SSLError as e:
        if not _cert_verify_failed(e):
            raise
        try:
            s.close()
        except Exception:
            pass
        if not TLS_DEGRADED[0]:
            TLS_DEGRADED[0] = True
            print(
                "[tls] certificate verification failed on this device; "
                "retrying without verification (old/missing CA store). "
                "Only rendezvous traffic uses this.",
                flush=True,
            )
        s = _open_plain(host, port, timeout)
        if hasattr(ssl, "_create_unverified_context"):
            ctx = ssl._create_unverified_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ctx.verify_mode = ssl.CERT_NONE
        s2 = ctx.wrap_socket(s, server_hostname=host)
        _sock_timeouts(s2, timeout)
        return s2


class _WSConn:
    """Minimal WebSocket client: binary messages, ping/pong, no deps."""

    def __init__(self, host, port, path, timeout=15, use_tls=True):
        self.sock = _open_connection(host, port, use_tls, timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n"
            % (path, host, port, key)
        )
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise OSError("websocket handshake closed")
            buf += chunk
            if len(buf) > 65536:
                raise OSError("websocket handshake too large")
        head, _, rest = buf.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        if "101" not in status:
            raise OSError("websocket handshake failed: %s" % status)
        self.buf = rest

    def _read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise OSError("websocket closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _send_frame(self, opcode, data):
        mask = os.urandom(4)
        n = len(data)
        if n < 126:
            hdr = bytes([0x80 | opcode, 0x80 | n])
        elif n < 65536:
            hdr = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack("!H", n)
        else:
            hdr = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack("!Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(hdr + mask + masked)

    def send_message(self, data):
        self._send_frame(2, data)

    def recv_message(self):
        payload = b""
        while True:
            h = self._read_exact(2)
            fin, op = h[0] & 0x80, h[0] & 0x0F
            ln = h[1] & 0x7F
            masked = h[1] & 0x80
            if ln == 126:
                ln = struct.unpack("!H", self._read_exact(2))[0]
            elif ln == 127:
                ln = struct.unpack("!Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if masked else None
            data = self._read_exact(ln) if ln else b""
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if op == 9:  # ping -> pong, keep reading
                self._send_frame(10, data)
                continue
            if op == 8:
                raise OSError("websocket close frame")
            if op in (0, 1, 2):
                payload += data
                if fin:
                    return payload

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def _enc_str(s):
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("!H", len(b)) + b


def _enc_rem(n):
    out = b""
    while True:
        d = n % 128
        n //= 128
        if n > 0:
            out += bytes([d | 0x80])
        else:
            out += bytes([d])
            break
    return out


class _MQTTConn:
    """One MQTT 3.1.1 session over a WS or raw-TCP transport."""

    def __init__(self, transport, sock=None, ws=None):
        self.transport = transport  # "ws" or "tcp"
        self.sock = sock
        self.ws = ws
        self.buf = b""

    @classmethod
    def over_ws(cls, host, port, path, timeout=15, use_tls=True):
        return cls("ws", ws=_WSConn(host, port, path, timeout, use_tls))

    @classmethod
    def over_tcp(cls, host, port, use_tls, timeout=12):
        return cls("tcp", sock=_open_connection(host, port, use_tls, timeout))

    def _fill(self):
        if self.transport == "ws":
            self.buf += self.ws.recv_message()
        else:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise OSError("mqtt tcp closed")
            self.buf += chunk

    def send(self, packet):
        if self.transport == "ws":
            self.ws.send_message(packet)
        else:
            self.sock.sendall(packet)

    def recv_packet(self):
        """Return (packet_type, flags, body). Raises on close/timeout."""
        while True:
            if len(self.buf) >= 2:
                # Decode remaining-length varint.
                i = 1
                rem = 0
                mult = 1
                complete = True
                while True:
                    if i >= len(self.buf):
                        complete = False
                        break
                    b = self.buf[i]
                    i += 1
                    rem += (b & 127) * mult
                    mult *= 128
                    if not (b & 128):
                        break
                if complete and len(self.buf) >= i + rem:
                    head = self.buf[0]
                    body = self.buf[i:i + rem]
                    self.buf = self.buf[i + rem:]
                    return head >> 4, head & 0x0F, body
            self._fill()

    def connect(self, client_id):
        var = _enc_str("MQTT") + bytes([4, 0x02]) + struct.pack("!H", 60)
        body = var + _enc_str(client_id)
        self.send(bytes([0x10]) + _enc_rem(len(body)) + body)
        ptype, _, body = self.recv_packet()
        if ptype != 2 or len(body) < 2 or body[1] != 0:
            raise OSError("MQTT CONNACK refused (type=%s body=%s)" % (ptype, body.hex()))

    def ping(self):
        self.send(bytes([0xC0, 0x00]))

    def publish_qos1(self, topic, payload, packet_id=7):
        var = _enc_str(topic) + struct.pack("!H", packet_id)
        pkt = bytes([0x33]) + _enc_rem(len(var) + len(payload)) + var + payload  # QoS1 + RETAIN
        self.send(pkt)
        while True:
            ptype, _, body = self.recv_packet()
            if ptype == 4:  # PUBACK
                if len(body) >= 2 and struct.unpack("!H", body[:2])[0] == packet_id:
                    return
            # Any other packet (PINGRESP etc.) is fine; keep waiting.

    def subscribe_read(self, topic, packet_id=9, wait_s=10):
        """SUBSCRIBE and return the retained payload for topic, or None."""
        body = struct.pack("!H", packet_id) + _enc_str(topic) + bytes([1])
        self.send(bytes([0x82]) + _enc_rem(len(body)) + body)
        deadline = time.time() + wait_s
        pinged = False
        while time.time() < deadline:
            try:
                ptype, flags, body = self.recv_packet()
            except (OSError, socket.error):
                if not pinged:
                    # Quiet broker or slow retained delivery: nudge with
                    # PINGREQ once, then keep waiting out the deadline.
                    try:
                        self.ping()
                    except Exception:
                        return None
                    pinged = True
                    continue
                return None
            if ptype == 3:  # PUBLISH
                if len(body) < 2:
                    continue
                tl = struct.unpack("!H", body[:2])[0]
                tpc = body[2:2 + tl].decode("utf-8", "replace")
                off = 2 + tl
                if (flags >> 1) & 3:  # QoS > 0 carries a packet id
                    off += 2
                if tpc == topic:
                    return body[off:]
            # SUBACK / PINGRESP / anything else: keep waiting.
        return None

    def close(self):
        try:
            self.send(bytes([0xE0, 0x00]))  # DISCONNECT
        except Exception:
            pass
        try:
            if self.transport == "ws":
                self.ws.close()
            elif self.sock:
                self.sock.close()
        except Exception:
            pass


def _mqtt_client_id(tag):
    return "bronode-%s-%s" % (tag, uuid.uuid4().hex[:10])


def _broker_transports(broker):
    """Yield (label, connect_fn) for one broker: WSS first, then plain
    WS (for devices whose TLS cannot work at all), then raw TCP."""
    for host, port, path in broker["wss"]:
        yield (
            "wss://%s:%d%s" % (host, port, path),
            lambda h=host, p=port, pa=path: _MQTTConn.over_ws(h, p, pa, timeout=15),
        )
    for host, port, path in broker.get("ws", []):
        yield (
            "ws://%s:%d%s" % (host, port, path),
            lambda h=host, p=port, pa=path: _MQTTConn.over_ws(
                h, p, pa, timeout=15, use_tls=False
            ),
        )
    for host, port, use_tls in broker["tcp"]:
        scheme = "mqtts" if use_tls else "mqtt"
        yield (
            "%s://%s:%d" % (scheme, host, port),
            lambda h=host, p=port, t=use_tls: _MQTTConn.over_tcp(h, p, t, timeout=10),
        )


def mqtt_publish(topic, payload):
    """Publish a retained QoS1 message to each broker. Returns the list
    of broker names that accepted it (empty = total failure)."""
    done = []
    for broker in MQTT_BROKERS:
        last_err = None
        broker_ok = False
        for label, connect in _broker_transports(broker):
            conn = None
            try:
                conn = connect()
                conn.connect(_mqtt_client_id("pub"))
                conn.publish_qos1(topic, payload)
                done.append("%s via %s" % (broker["name"], label))
                broker_ok = True
                break
            except Exception as e:
                last_err = e
            finally:
                if conn:
                    conn.close()
        if not broker_ok:
            print(
                "[rendezvous] mqtt publish to %s failed (%s); will retry"
                % (broker["name"], last_err),
                flush=True,
            )
    return done


def mqtt_fetch(topic, wait_s=10):
    """Read the retained message for topic. Returns (payload, label)
    or (None, None). Tries brokers in order, WSS before TCP."""
    for broker in MQTT_BROKERS:
        for label, connect in _broker_transports(broker):
            conn = None
            try:
                conn = connect()
                conn.connect(_mqtt_client_id("sub"))
                payload = conn.subscribe_read(topic, wait_s=wait_s)
                if payload is not None:
                    return payload, "%s via %s" % (broker["name"], label)
                # Connected fine but nothing retained here: the answer
                # cannot differ per transport on the same broker.
                break
            except Exception:
                continue
            finally:
                if conn:
                    conn.close()
    return None, None


def publish_rendezvous(port, name):
    """Publish the payload via MQTT (primary) and ntfy (secondary).
    Returns True if at least one rendezvous accepted it."""
    payload = rendezvous_payload(port, name)
    ok = False
    try:
        if mqtt_publish(mqtt_rendezvous_topic(), json.dumps(payload).encode()):
            ok = True
    except Exception as e:
        print("[rendezvous] mqtt publish failed (%s); will retry" % e, flush=True)
    if publish_ntfy(payload):
        ok = True
    return ok


def rendezvous_loop(port, name):
    first = True
    while True:
        ok = publish_rendezvous(port, name)
        if first:
            print(
                "[rendezvous] first publish %s"
                % ("ok" if ok else "FAILED; retrying every 60s"),
                flush=True,
            )
            first = False
        time.sleep(60)


# --- optional Cloudflare quick tunnel ---


def tunnel_loop(port, name):
    global TUNNEL_URL
    exe = shutil.which("cloudflared")
    if exe:
        try:
            p = subprocess.Popen(
                [exe, "tunnel", "--url", "http://127.0.0.1:%d" % port],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            # Quick-tunnel hostnames always contain hyphens (random
            # word combos). A bare "api.trycloudflare.com" also fits
            # the naive pattern and appears in cloudflared's early log
            # lines, so require a hyphen and skip the api host.
            pat = re.compile(r"https://[a-z0-9]+(?:-[a-z0-9]+)+\.trycloudflare\.com")
            announced = False
            for line in p.stdout:
                if announced:
                    # Keep draining: if nobody reads the pipe,
                    # cloudflared blocks on its own log writes once
                    # the buffer fills, its keepalives stall, and the
                    # edge drops the tunnel (Cloudflare error 530).
                    continue
                m = pat.search(line)
                if m:
                    with TUNNEL_LOCK:
                        TUNNEL_URL = m.group(0)
                    print("[tunnel] public URL: %s" % TUNNEL_URL, flush=True)
                    publish_rendezvous(port, name)
                    announced = True
            if announced:
                return
            print("[tunnel] cloudflared exited without a URL", flush=True)
        except Exception as e:
            print("[tunnel] cloudflared failed to start: %s" % e, flush=True)
    # Fallback for devices where cloudflared is missing or cannot run
    # (old Android/Termux, 32-bit builds, old distros): an ssh reverse
    # tunnel via localhost.run, when ssh exists.
    ssh = shutil.which("ssh")
    if not ssh:
        return
    try:
        p = subprocess.Popen(
            [
                ssh,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ServerAliveInterval=30",
                "-o",
                "ExitOnForwardFailure=yes",
                "-R",
                "80:127.0.0.1:%d" % port,
                "nokey@localhost.run",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
    except Exception as e:
        print("[tunnel] ssh tunnel failed to start: %s" % e, flush=True)
        return
    pat = re.compile(r"https://[a-z0-9.-]+\.(?:localhost\.run|lhr\.life)")
    # localhost.run's ssh banner prints its admin/docs links
    # (admin.localhost.run, www.localhost.run) BEFORE the real tunnel
    # hostname. Skip those or the node announces a URL that 404s.
    skip_hosts = ("admin.localhost.run", "www.localhost.run",
                  "admin.lhr.life", "www.lhr.life")
    announced = False
    for line in p.stdout:
        if announced:
            # Keep draining (see cloudflared note): an undrained
            # pipe stalls ssh and localhost.run drops the tunnel.
            continue
        m = pat.search(line)
        if m and m.group(0).split("://", 1)[1] not in skip_hosts:
            with TUNNEL_LOCK:
                TUNNEL_URL = m.group(0)
            print("[tunnel] public URL (ssh): %s" % TUNNEL_URL, flush=True)
            publish_rendezvous(port, name)
            announced = True


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
    if sys.version_info < (3, 6):
        print(
            "bro-node needs Python 3.6 or newer (this is %s). "
            "Update Python on this device and try again."
            % sys.version.split()[0],
            flush=True,
        )
        return
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
    print(
        "  Python %s | CA bundle: %s"
        % (sys.version.split()[0], _ca_bundle() or "system default"),
        flush=True,
    )
    print("=" * 56, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
