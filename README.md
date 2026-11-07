# bro-node

A tiny server you run on any of your machines so bro can get on it and work:
run commands, move files, and use the machine as extra processing power.
One Python file, standard library only, nothing else to install beyond
Python 3. Works on Linux and on Android through Termux.

This is separate from the older linuxtomux bridge: bro-node is the
stripped-down version. Start server, hand bro the connect line, done.

## Termux (Android phone)

Paste this into Termux:

```sh
pkg update -y && pkg install -y python git termux-api
git clone https://github.com/jaykk99/bro-node
cd bro-node && python server.py
```

Keep the phone awake while it works:

```sh
termux-wake-lock
```

## Linux (PC, laptop, server)

```sh
git clone https://github.com/jaykk99/bro-node
cd bro-node && python3 server.py
```

To keep it running after you close the terminal:

```sh
cd bro-node && nohup python3 server.py > ~/.bro-node/server.log 2>&1 &
```

## Hand it to bro

On start, the server prints a line like:

```
CONNECT LINE for bro: bro-node http://<this-machine-ip>:8899 key <pairing-key>
```

Send that line to bro. With it he can check the machine's status, run
commands, start long background jobs, and move files on and off.

- Same wifi/network: the printed address just works.
- From anywhere else: put both machines on Tailscale and use the
  machine's Tailscale address instead. Do not port-forward this server
  to the open internet; the pairing key is the only lock on the door.

## What bro can do with it

- `GET /api/status` — hostname, cores, RAM, disk, battery (Termux), IPs.
- `POST /api/exec` — run a shell command, get stdout/stderr/exit back.
- `POST /api/job` + `GET /api/job/<id>` — long background jobs with logs.
- `GET /api/file?path=` / `POST /api/file` — download / upload files.
- `client.py` in this repo is the matching command-line client.

## Safety shape

- Every API call needs the pairing key (`X-Pair-Key` header). The key is
  generated once and stored at `~/.bro-node/pairing-key` with 0600 perms.
- A small guard blocks catastrophic typos (`rm -rf /`, mkfs, dd onto a
  raw device, shutdown). It is a speed bump, not a sandbox: whoever holds
  the key is trusted, so treat the key like a password.
- State and job logs live in `~/.bro-node/`.
