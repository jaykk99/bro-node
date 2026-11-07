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

Connect mode looks the node's rendezvous payload up, in order:
  1. MQTT: a retained message on public brokers (topic is
     bronode/<sha256(access_key)>), read over WSS.
  2. ntfy: the same payload on an ntfy topic derived from the key.
Then it tries, in order: tunnel_url, Tailscale IPs, LAN IPs,
verifying each candidate with an authenticated /api/status call.

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
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid

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


# --- MQTT rendezvous lookup (primary) ---
#
# Same minimal MQTT 3.1.1 implementation as server.py (vendored there,
# shared here): brokers tried in order, WSS before plain TCP, sockets
# blocking with kernel SO_RCVTIMEO timeouts, http(s)_proxy honoured
# via CONNECT for the WSS connections. When the websocket-client
# library is importable it gets one quick attempt at the primary
# broker first; the vendored stdlib client is the fallback and the
# path that works behind strict egress proxies.

MQTT_BROKERS = [
    {
        "name": "emqx",
        "wss": [("broker.emqx.io", 8084, "/mqtt")],
        "tcp": [("broker.emqx.io", 1883, False), ("broker.emqx.io", 8883, True)],
    },
    {
        "name": "mosquitto",
        "wss": [("test.mosquitto.org", 8081, "/mqtt"), ("test.mosquitto.org", 8081, "/")],
        "tcp": [("test.mosquitto.org", 1883, False), ("test.mosquitto.org", 8883, True)],
    },
]


def mqtt_rendezvous_topic(key):
    return "bronode/" + hashlib.sha256(key.encode()).hexdigest()


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


def _open_connection(host, port, use_tls, timeout=15):
    """TCP (optionally via proxy CONNECT) + optional TLS. Blocking mode."""
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
    else:
        s = socket.create_connection((host, port), timeout=timeout)
        _sock_timeouts(s, timeout)
    if use_tls:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s, server_hostname=host)
        _sock_timeouts(s, timeout)
    return s


class _WSConn:
    """Minimal WebSocket client: binary messages, ping/pong, no deps."""

    def __init__(self, host, port, path, timeout=15):
        self.sock = _open_connection(host, port, True, timeout)
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
    def over_ws(cls, host, port, path, timeout=15):
        return cls("ws", ws=_WSConn(host, port, path, timeout))

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
    """Yield (label, connect_fn) for one broker, WSS first, then TCP."""
    for host, port, path in broker["wss"]:
        yield (
            "wss://%s:%d%s" % (host, port, path),
            lambda h=host, p=port, pa=path: _MQTTConn.over_ws(h, p, pa, timeout=15),
        )
    for host, port, use_tls in broker["tcp"]:
        scheme = "mqtts" if use_tls else "mqtt"
        yield (
            "%s://%s:%d" % (scheme, host, port),
            lambda h=host, p=port, t=use_tls: _MQTTConn.over_tcp(h, p, t, timeout=10),
        )


def _mqtt_fetch_ws_lib(topic, wait_s=8):
    """One quick retained read via the websocket-client library, if it
    is importable. Returns payload bytes or None."""
    try:
        import websocket  # websocket-client
    except ImportError:
        return None
    host, port, path = MQTT_BROKERS[0]["wss"][0]
    url = "wss://%s:%d%s" % (host, port, path)
    ws = None
    try:
        ws = websocket.create_connection(url, timeout=wait_s, subprotocols=["mqtt"])
        ws.settimeout(wait_s)
        buf = b""

        def recv_packet():
            nonlocal buf
            while True:
                if len(buf) >= 2:
                    i = 1
                    rem = 0
                    mult = 1
                    complete = True
                    while True:
                        if i >= len(buf):
                            complete = False
                            break
                        b = buf[i]
                        i += 1
                        rem += (b & 127) * mult
                        mult *= 128
                        if not (b & 128):
                            break
                    if complete and len(buf) >= i + rem:
                        head = buf[0]
                        body = buf[i:i + rem]
                        buf = buf[i + rem:]
                        return head >> 4, head & 0x0F, body
                chunk = ws.recv()
                if isinstance(chunk, str):
                    chunk = chunk.encode()
                if not chunk:
                    raise OSError("ws-lib closed")
                buf += chunk

        var = _enc_str("MQTT") + bytes([4, 0x02]) + struct.pack("!H", 60)
        body = var + _enc_str(_mqtt_client_id("sub"))
        ws.send_binary(bytes([0x10]) + _enc_rem(len(body)) + body)
        ptype, _, body = recv_packet()
        if ptype != 2 or len(body) < 2 or body[1] != 0:
            return None
        sbody = struct.pack("!H", 9) + _enc_str(topic) + bytes([1])
        ws.send_binary(bytes([0x82]) + _enc_rem(len(sbody)) + sbody)
        deadline = time.time() + wait_s
        while time.time() < deadline:
            ptype, flags, body = recv_packet()
            if ptype == 3 and len(body) >= 2:
                tl = struct.unpack("!H", body[:2])[0]
                tpc = body[2:2 + tl].decode("utf-8", "replace")
                off = 2 + tl
                if (flags >> 1) & 3:
                    off += 2
                if tpc == topic:
                    return body[off:]
        return None
    except Exception:
        return None
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass


def mqtt_fetch(topic, wait_s=10):
    """Read the retained message for topic. Returns (payload, label)
    or (None, None). websocket-client gets one shot at the primary
    broker; the vendored stdlib client then walks all brokers."""
    payload = _mqtt_fetch_ws_lib(topic, wait_s=8)
    if payload is not None:
        host, port, path = MQTT_BROKERS[0]["wss"][0]
        return payload, "emqx via wss://%s:%d%s (websocket-client)" % (host, port, path)
    for broker in MQTT_BROKERS:
        for label, connect in _broker_transports(broker):
            conn = None
            try:
                conn = connect()
                conn.connect(_mqtt_client_id("sub"))
                payload = conn.subscribe_read(topic, wait_s=wait_s)
                if payload is not None:
                    return payload, "%s via %s" % (broker["name"], label)
                break  # connected but nothing retained on this broker
            except Exception:
                continue
            finally:
                if conn:
                    conn.close()
    return None, None


def fetch_rendezvous_mqtt(pin, key):
    """Return (payload_dict, lookup_label) via MQTT, or (None, None)."""
    raw, label = mqtt_fetch(mqtt_rendezvous_topic(key))
    if raw is None:
        return None, None
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None, None
    if str(payload.get("pin")) != str(pin):
        return None, None
    return payload, "mqtt (%s)" % label


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
    """Find a reachable base URL for the node using only PIN + key.

    Lookup order: (1) MQTT retained read, (2) ntfy feed. Then dial
    candidates (tunnel, Tailscale, LAN), verifying each with an
    authenticated /api/status call."""
    payload, via = fetch_rendezvous_mqtt(pin, key)
    if not payload:
        payload = fetch_rendezvous(pin, key, ntfy_base)
        via = "ntfy"
    if not payload:
        raise RuntimeError("no rendezvous payload found for that PIN/key (is the node running?)")
    print("rendezvous lookup: found node via %s" % via, file=sys.stderr)
    age = int(time.time()) - int(payload.get("ts", 0) or 0)
    if age > 300:
        print(
            "warning: rendezvous payload is %ds old; the node may have "
            "restarted and rotated its access key" % age,
            file=sys.stderr,
        )
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
