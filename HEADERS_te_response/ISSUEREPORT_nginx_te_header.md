# HTTP/2: `te` header with values other than "trailers" not rejected as malformed

## Summary

Nginx accepts HTTP/2 requests containing `te` header values other than `"trailers"` (e.g., `te: chunked`, `te: trailers, chunked`) without treating the message as malformed. RFC 9113 §8.2.2 requires that when `te` is present in an HTTP/2 request, it MUST NOT contain any value other than `"trailers"`. Violation must result in a PROTOCOL_ERROR stream error (§8.1.1).

## Steps to Reproduce

1. Configure Nginx with HTTP/2 enabled and `proxy_pass` to an HTTP/1.1 backend.

2. Send an HTTP/2 request with an illegal `te` value:

```python
headers = [
    (b":method", b"POST"),
    (b":scheme", b"https"),
    (b":path", b"/test"),
    (b":authority", b"localhost:443"),
    (b"content-length", b"4"),
    (b"te", b"trailers, chunked"),
]
# Send via HEADERS frame, then DATA (4 bytes) with END_STREAM
```

3. Observe the response.

## Actual Result

Nginx returns a normal HTTP/2 response (HEADERS + DATA). No RST_STREAM is sent. The request is forwarded to the backend (with `te` stripped during translation).

## Expected Result

Nginx should reject the stream with RST_STREAM (PROTOCOL_ERROR) and not forward the request, consistent with HAProxy's behavior under identical conditions.

## Context

- Tested on `nginx:latest` (Docker Hub, 1.27.x/1.29.x)
- HAProxy correctly issues RST_STREAM PROTOCOL_ERROR for both `te: chunked` and `te: trailers, chunked`
- A patch for this exact issue was proposed on nginx-devel (2017-06-13, Piotr Sikora / Google) in `[PATCH 2 of 4] HTTP/2: reject HTTP/2 requests with invalid "TE" header value` but was never merged: http://nginx.org/pipermail/nginx-devel/2017-June/010113.html
- Related: trac #537 (TE header stripping during proxy, which mitigates forwarding but does not address H2-layer validation)

## Security Relevance

The `te` header is stripped during H2→H1 translation, which currently prevents the illegal value from reaching backends. However, this relies on translation-layer behavior rather than specification-mandated H2-layer validation. If `proxy_set_header TE $http_te;` is configured (or equivalent), the illegal value reaches the backend, potentially enabling TE-based request smuggling (same class as CVE-2025-4600).

## PoC Repository

https://github.com/APEvul-cyber/HTTP2_nginx_vul/tree/main/HEADERS_te_response
