# bro-node

A tiny server you run on any of your machines so bro can get on it and work:
run commands, move files, and use the machine as extra processing power.
One Python file, standard library only, nothing else to install beyond
Python 3.6 or newer. Works on Linux and on Android through Termux,
including older devices (see "Older Android / older Linux" below).

This is separate from the older linuxtomux bridge: bro-node is the
stripped-down version. Start the server, send bro two short things, done.

## Quick start (tablet / phone)

In Termux, run these one line at a time. Type a line, press Enter,
wait for it to finish, then type the next one:

```
pkg install -y python git termux-api
git clone https://github.com/jaykk99/bro-node
cd bro-node
termux-wake-lock
python server.py
```

When the server starts it prints a PIN and an ACCESS KEY. Send bro
both of those and nothing else. The key is new every start.

## No IP address needed

You do NOT give bro an IP address anymore. Every time the server starts
it prints a **PIN** and an **ACCESS KEY**:

```
================================================
  bro-node is running: <your machine>

  PIN:        123456
  ACCESS KEY: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

  Tell bro: PIN 123456 + ACCESS KEY (above)
  The access key is new every start. Keep this terminal open.
================================================
```

**Send bro the PIN and the ACCESS KEY. Nothing else.**

The access key is **different on every start**. Restart the server and
the old key stops working and a new one is printed, so every restart
means sending bro the new key. The node quietly publishes how to reach
it, so bro can find the machine from the PIN + key alone.

How the lookup works: the node publishes its reachability info as a
**retained message on a public MQTT broker** (EMQX, with the
test.mosquitto.org broker as fallback), on a topic derived from the
access key itself: `bronode/<sha256 of the access key>`. Only someone
holding the access key can derive that topic, so only key holders can
find the node. Bro's client reads that retained message first, then
dials the announced addresses (Cloudflare tunnel, Tailscale, LAN) and
verifies the node with the PIN + key before trusting it. An ntfy.sh
topic derived the same way is kept as a secondary lookup. The payload
is republished every 60 seconds, and a payload older than 5 minutes
warns that the node may have restarted and rotated its key.

## Termux (Android phone / tablet)

Run these commands in Termux, **one line at a time**. Type a line,
press Enter, wait for it to finish, then type the next one:

```
pkg install -y python git termux-api
```

```
git clone https://github.com/jaykk99/bro-node
```

```
cd bro-node
```

```
termux-wake-lock
```

```
python server.py
```

Then send bro the PIN and ACCESS KEY it prints.

## Linux (PC, laptop, server)

```sh
git clone https://github.com/jaykk99/bro-node
cd bro-node
python3 server.py
```

Then send bro the PIN and ACCESS KEY it prints.

To keep it running after you close the terminal:

```sh
cd bro-node && nohup python3 server.py > ~/.bro-node/server.log 2>&1 &
```

(The new PIN + key are in that log file. Remember: a restart means a
new key.)

## Older Android / older Linux (v2.2)

Old gear works. The floor is **Python 3.6**, so an old Termux, an old
Android tablet, or an old Linux distro (Debian 9 era, CentOS 7) can run
the node as long as it has Python 3.6+:

```sh
git clone https://github.com/jaykk99/bro-node
cd bro-node
python3 server.py
```

(If `git` is missing too, download just the one file and run it:
`curl -LO https://raw.githubusercontent.com/jaykk99/bro-node/main/server.py`
then `python3 server.py`.)

What v2.2 fixes for old devices:

- **No CA certificates needed.** Old Termux installs fail with
  `CERTIFICATE_VERIFY_FAILED` because they have no CA store. The node
  now hunts for a CA bundle in the usual places (including Termux's own
  paths), and if verification still fails it retries the rendezvous
  connection without verification instead of dying. The startup banner
  shows which CA bundle it found. Installing `ca-certificates`
  (`pkg install -y ca-certificates`) is still the cleaner fix when the
  package is available.
- **Plain broker transports.** If TLS cannot work at all on the
  device, the rendezvous also tries plain (unencrypted) WebSocket and
  plain MQTT to the same public brokers.
- **No cloudflared needed.** If `cloudflared` is missing or cannot run
  on the device (old/32-bit builds), the node falls back to an `ssh`
  reverse tunnel (localhost.run) when `ssh` is installed, and still
  announces its LAN address either way.
- **Old Python shims.** No 3.7+-only calls remain; if Python is older
  than 3.6 the node says so in plain words at startup.

## Reaching the node from outside home wifi (optional)

On the same wifi/network, bro can reach the node directly once another
bro-connected machine is on that network, and over Tailscale if both
ends run it.

For direct access from anywhere, install `cloudflared` on the node
machine. bro-node starts a Cloudflare tunnel by itself when it finds
the binary, and publishes the tunnel address with the rendezvous info:

```
pkg install cloudflared
```

(Termux: `pkg install cloudflared`. Linux: install the cloudflared
package for your distro.)

Without cloudflared, bro needs a Tailscale or same-network path from
another connected node. Do not port-forward this server to the open
internet yourself; the PIN + access key are the only lock on the door.

## What bro can do with it

- `GET /api/status` — hostname, cores, RAM, disk, battery (Termux), IPs.
- `POST /api/exec` — run a shell command, get stdout/stderr/exit back.
- `POST /api/job` + `GET /api/job/<id>` — long background jobs with logs.
- `GET /api/file?path=` / `POST /api/file` — download / upload files.
- `client.py` in this repo is the matching command-line client:

```sh
python3 client.py --pin 123456 --key <access_key> status
python3 client.py --pin 123456 --key <access_key> exec "uname -a"
```

## Safety shape

- Every API call needs BOTH the PIN (`X-Pin` header) and the current
  session access key (`X-Pair-Key` header). Both are generated fresh
  with the `secrets` module on every start and are never stored on disk.
- A small guard blocks catastrophic typos (`rm -rf /`, mkfs, dd onto a
  raw device, shutdown). It is a speed bump, not a sandbox: whoever
  holds the PIN + key is trusted, so treat them like a password.
- Job logs live in `~/.bro-node/` (override with `BRO_NODE_HOME`).
