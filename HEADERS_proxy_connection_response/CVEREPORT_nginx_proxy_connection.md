# Nginx HTTP/2: Forbidden `proxy-connection` Header Accepted and Forwarded to HTTP/1.1 Backend

## Summary

Improper input validation in `ngx_http_v2_module` in Nginx allows remote attackers to inject the `proxy-connection` header into HTTP/1.1 backend requests via crafted HTTP/2 HEADERS frames, because the HTTP/2 layer does not treat `proxy-connection` as a connection-specific header field per RFC 9113 §8.2.2.

## Affected Software

- **Product**: Nginx (open source)
- **Confirmed on**: Docker image `nginx:latest` (1.27.x / 1.29.x mainline)
- **Likely affected**: All versions with `http2 on` and `proxy_pass` to HTTP/1.1 backends
- **CWE**: CWE-444 (Inconsistent Interpretation of HTTP Requests), CWE-20 (Improper Input Validation)

## Description

RFC 9113 (HTTP/2) §8.2.2 defines the following as connection-specific header fields that MUST NOT appear in HTTP/2 messages:

- `connection`
- `keep-alive`
- `proxy-connection`
- `transfer-encoding`
- `upgrade`

Per §8.1, any HTTP/2 message containing these fields MUST be treated as malformed, resulting in a stream error of type `PROTOCOL_ERROR`, and intermediaries MUST NOT forward such messages.

Nginx's HTTP/2 module validates `connection`, `transfer-encoding`, and `upgrade` during HPACK header processing, but **does not validate `proxy-connection`**. As a result:

1. An HTTP/2 request containing `proxy-connection` is accepted without error.
2. The request is translated to HTTP/1.1 and forwarded to the backend.
3. The `proxy-connection` header **reaches the backend verbatim**, unlike the other connection-specific headers which are rejected or stripped.

Comparison with other major proxies under identical test conditions:

| Proxy | Behavior | RFC 9113 Compliant |
|-------|----------|-------------------|
| HAProxy | RST_STREAM PROTOCOL_ERROR | Yes |
| Traefik | Rejects / does not forward | Yes |
| Caddy | Rejects / does not forward | Yes |
| **Nginx** | **Accepts and forwards to backend** | **No** |

## Impact

**Direct**: An attacker can inject arbitrary `Proxy-Connection` values into HTTP/1.1 requests received by backend servers. The forbidden header crosses the HTTP/2 → HTTP/1.1 protocol boundary, violating the security invariant that RFC 9113 §8.2.2 was designed to enforce.

**Escalated** (conditional on backend behavior): Legacy HTTP/1.1 backends or intermediate proxies that interpret `Proxy-Connection` with `Connection`-like hop-by-hop semantics may:
- Strip headers designated by `Proxy-Connection` values (e.g., `proxy-connection: keep-alive, transfer-encoding`)
- Cause CL/TE desynchronization leading to HTTP request smuggling
- Alter connection persistence semantics between proxy and backend

This attack class is documented in existing CVEs:
- CVE-2026-26365 (Akamai CDN, `Connection: Transfer-Encoding` smuggling)
- CVE-2023-25690 (Apache HTTP Server, request smuggling via header manipulation)

## Root Cause

Nginx trac ticket **#915** and its duplicate **#2078** document the same class of issue for the `Upgrade` header (also connection-specific per §8.2.2) being forwarded through HTTP/2 proxying. The `proxy-connection` header was not included in the H2 header validation blocklist in `ngx_http_v2_module`.

## Proof of Concept

### Environment

- Nginx `nginx:latest` configured as TLS HTTP/2 reverse proxy → HTTP/1.1 backend
- Backend: raw HTTP/1.1 logging server capturing complete request bytes

### Reproduction

Send an HTTP/2 request with a `proxy-connection` header using raw frames (Python `hyperframe` + `hpack`):

```python
headers = [
    (b":method", b"POST"),
    (b":scheme", b"https"),
    (b":path", b"/test"),
    (b":authority", b"target:443"),
    (b"proxy-connection", b"keep-alive"),
    (b"content-length", b"3"),
]
```

1. Establish TLS connection with ALPN `h2`
2. Send HTTP/2 connection preface + SETTINGS
3. Send HEADERS frame with the above headers (including `proxy-connection`)
4. Send DATA frame with body, END_STREAM set

### Observed Result

Backend receives:

```http
POST /test HTTP/1.1
Host: target
Content-Length: 3
proxy-connection: keep-alive

...
```

The `proxy-connection: keep-alive` header is present in the HTTP/1.1 request. HAProxy, Traefik, and Caddy all reject this request at the HTTP/2 layer with PROTOCOL_ERROR under identical conditions.

### Expected Result

Nginx should treat the stream as malformed and respond with RST_STREAM (PROTOCOL_ERROR), without forwarding the request.

## Suggested Fix

Add `proxy-connection` to the connection-specific header field blocklist in `ngx_http_v2_module`, alongside the existing checks for `connection`, `transfer-encoding`, and `upgrade`. Upon encountering `proxy-connection` in HTTP/2 headers:

1. Treat the request as malformed per RFC 9113 §8.1
2. Emit RST_STREAM with PROTOCOL_ERROR
3. Do not forward the request to any backend

Alternatively, at minimum, strip `proxy-connection` during H2→H1 translation (similar to current handling of `connection`).

## References

- RFC 9113 §8.2.2 — Connection-Specific Header Fields
- RFC 9113 §8.1 — Malformed Messages
- Nginx trac #915 — `Upgrade` header forwarded over H2 (same class)
- Nginx trac #2078 — Duplicate of #915
- CVE-2026-26365 — Akamai `Connection: Transfer-Encoding` smuggling
- CVE-2023-25690 — Apache HTTP Server request smuggling
- PoC Repository — https://github.com/APEvul-cyber/HTTP2_nginx_vul/tree/main/HEADERS_proxy_connection_response
