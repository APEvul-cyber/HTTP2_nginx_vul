# Nginx HTTP/2: Illegal `te` Header Values Accepted Without PROTOCOL_ERROR

## Summary

Improper input validation in `ngx_http_v2_module` in Nginx allows remote attackers to send HTTP/2 requests with illegal `te` header values (e.g., `te: chunked`, `te: trailers, chunked`) without receiving a stream error, because the HTTP/2 layer does not enforce the `"trailers"`-only constraint required by RFC 9113 §8.2.2.

## Affected Software

- **Product**: Nginx (open source)
- **Confirmed on**: Docker image `nginx:latest` (1.27.x / 1.29.x mainline)
- **Likely affected**: All versions with `http2 on`
- **CWE**: CWE-20 (Improper Input Validation)

## Description

RFC 9113 §8.2.2 states:

> The TE header field [...] MAY be present in an HTTP/2 request; when it is, it MUST NOT contain any value other than "trailers".

Any HTTP/2 message with a `te` value other than the bare `"trailers"` MUST be treated as malformed (§8.1.1), resulting in a stream error of type PROTOCOL_ERROR, and MUST NOT be forwarded by intermediaries.

Nginx accepts HTTP/2 requests with illegal `te` values (`te: chunked`, `te: trailers, chunked`, etc.) without any error. The request is processed normally and forwarded to the HTTP/1.1 backend. The `te` header is stripped during H2→H1 translation (a mitigating factor), but the acceptance at the H2 layer violates the specification.

### Historical Context

A patch to fix this exact issue was proposed on the nginx-devel mailing list on **2017-06-13** by Piotr Sikora (Google): `[PATCH 2 of 4] HTTP/2: reject HTTP/2 requests with invalid "TE" header value`. The patch added validation in `ngx_http_process_te()` to check that `te` values are exactly `"trailers"` for HTTP/2 streams. This patch was never merged into the Nginx mainline.

Comparison under identical test conditions:

| Proxy | `te: trailers, chunked` | `te: chunked` | RFC 9113 Compliant |
|-------|------------------------|----------------|-------------------|
| HAProxy | RST_STREAM PROTOCOL_ERROR | RST_STREAM PROTOCOL_ERROR | Yes |
| **Nginx** | **Accepted (no error)** | **Accepted (no error)** | **No** |

## Impact

**Direct**: Nginx accepts HTTP/2 requests that the specification mandates MUST be treated as malformed. The H2 layer, which should be the first line of defense against connection-specific header abuse, is bypassed.

**Escalated** (conditional): The `te` header is currently stripped during H2→H1 translation. However, if an administrator configures `proxy_set_header TE $http_te;`, the illegal value would be forwarded to the backend. Combined with a backend that acts on `TE: chunked` (mapping it to `Transfer-Encoding: chunked`), this could enable CL/TE request smuggling — the same class of attack as CVE-2025-4600 (Google Cloud LB, TE.0 smuggling).

## Proof of Concept

### Reproduction

```python
headers = [
    (b":method", b"POST"),
    (b":scheme", b"https"),
    (b":path", b"/test"),
    (b":authority", b"target:443"),
    (b"content-length", b"4"),
    (b"te", b"trailers, chunked"),
]
```

1. Establish TLS connection with ALPN `h2`
2. Send HTTP/2 connection preface + SETTINGS
3. Send HEADERS frame with the above headers
4. Send DATA frame (4 bytes), END_STREAM set

### Observed Result

Nginx returns H2 HEADERS + DATA response (200 OK or backend response). No RST_STREAM, no GOAWAY. HAProxy returns RST_STREAM PROTOCOL_ERROR under identical conditions.

### Expected Result

Nginx should treat the stream as malformed and respond with RST_STREAM (PROTOCOL_ERROR).

## Suggested Fix

Implement or re-apply the 2017 Piotr Sikora patch. In the HTTP/2 header processing path (`ngx_http_process_te`):

1. For HTTP/2 streams, check that `te` value equals `"trailers"` (case-insensitive, after trimming OWS)
2. If not, return `NGX_HTTP_BAD_REQUEST` / emit RST_STREAM with PROTOCOL_ERROR
3. Do not forward the request

## References

- RFC 9113 §8.2.2 — `te` header constraints in HTTP/2
- RFC 9113 §8.1.1 — Malformed message handling
- nginx-devel 2017-06-13 — Piotr Sikora patch (never merged): http://nginx.org/pipermail/nginx-devel/2017-June/010113.html
- Nginx trac #537 — TE hop-by-hop stripping (mitigating factor)
- CVE-2025-4600 — Google Cloud LB TE.0 smuggling (same attack class)
- CVE-2026-26365 — Akamai `Connection: Transfer-Encoding` smuggling
- PoC Repository — https://github.com/APEvul-cyber/HTTP2_nginx_vul/tree/main/HEADERS_te_response
