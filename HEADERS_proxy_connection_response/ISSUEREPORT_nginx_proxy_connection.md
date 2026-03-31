# HTTP/2: `proxy-connection` header not treated as connection-specific — accepted and forwarded to HTTP/1.1 backend

## Summary

When Nginx receives an HTTP/2 request containing a `proxy-connection` header, it does not treat the message as malformed. Instead, the header is forwarded verbatim to the HTTP/1.1 backend during H2→H1 translation.

RFC 9113 §8.2.2 lists `proxy-connection` as a connection-specific header field that MUST NOT appear in HTTP/2 messages. Any such message MUST be treated as malformed (§8.1), resulting in a stream error of type PROTOCOL_ERROR.

Nginx correctly validates other connection-specific headers (`connection`, `transfer-encoding`, `upgrade`) in the HTTP/2 path, but `proxy-connection` is missing from this validation.

## Steps to Reproduce

1. Configure Nginx as an HTTP/2 reverse proxy to an HTTP/1.1 backend:

```nginx
server {
    listen 443 ssl;
    http2 on;
    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    location / {
        proxy_pass http://backend:8888;
        proxy_set_header Host $host;
    }
}
```

2. Send an HTTP/2 request containing `proxy-connection`:

```python
# Using hpack + hyperframe
headers = [
    (b":method", b"POST"),
    (b":scheme", b"https"),
    (b":path", b"/test"),
    (b":authority", b"localhost:443"),
    (b"proxy-connection", b"keep-alive"),
    (b"content-length", b"3"),
]
# Send via HEADERS frame on stream 1, then DATA with END_STREAM
```

3. Observe backend request logs.

## Actual Result

Backend receives:

```http
POST /test HTTP/1.1
Host: localhost
Content-Length: 3
proxy-connection: keep-alive

...
```

The `proxy-connection` header passes through.

## Expected Result

Nginx should reject the HTTP/2 stream with RST_STREAM (PROTOCOL_ERROR) and not forward the request, consistent with its handling of `connection`, `transfer-encoding`, and `upgrade`.

## Context

- Tested on `nginx:latest` (Docker Hub, 1.27.x/1.29.x)
- HAProxy, Traefik, and Caddy all correctly reject or strip this header under the same conditions
- Related tickets: #915 (`Upgrade` header forwarded over H2), #2078 (duplicate of #915)
- RFC 9113 §8.2.2 explicitly enumerates `proxy-connection` alongside the other connection-specific fields

## Security Relevance

Legacy HTTP/1.1 backends or intermediate proxies may interpret `Proxy-Connection` with hop-by-hop semantics (similar to `Connection`), potentially leading to header stripping or message framing inconsistencies. This is the same class of issue as CVE-2026-26365 (Akamai) and CVE-2023-25690 (Apache).

## PoC Repository

https://github.com/APEvul-cyber/HTTP2_nginx_vul/tree/main/HEADERS_proxy_connection_response
