# nginx HTTP/2 accepts and forwards `proxy-connection`

**Affected:** nginx `ngx_http_v2_module` (`nginx:latest` 1.27 / 1.29, `http2 on` + `proxy_pass`).  
**CWE:** CWE-444, CWE-20

RFC 9113 §8.2.2 lists `proxy-connection` as a connection-specific field. It MUST NOT appear in HTTP/2. The message MUST be malformed (`PROTOCOL_ERROR`) and MUST NOT be forwarded.

nginx checks `connection`, `transfer-encoding`, and `upgrade` in the H2 path. It does not check `proxy-connection`. The header is accepted and copied onto the HTTP/1.1 backend request.

HAProxy / Traefik / Caddy reject or drop it.

**Impact:** an HTTP/2 client can inject `Proxy-Connection` into the backend H1 request. A backend that treats it like `Connection` may strip hop-by-hop fields or desync framing (same class as CVE-2023-25690).

## Reproduce

```
:method = POST
:scheme = https
:path = /test
:authority = target
proxy-connection = keep-alive
content-length = 3
```

Backend sees:

```
POST /test HTTP/1.1
Host: target
Content-Length: 3
proxy-connection: keep-alive
```

**Expected:** `RST_STREAM` (`PROTOCOL_ERROR`), not forwarded.

See `poc.py`.

## Fix

Treat `proxy-connection` like `connection` in `ngx_http_v2_module`: reject the stream, do not proxy. Stripping on H2→H1 is a weaker fallback.

## References

- RFC 9113 §8.2.2, §8.1
- nginx trac #915 / #2078 (`Upgrade` forwarded over H2)
- CVE-2023-25690
- https://github.com/APEvul-cyber/HTTP2_nginx_vul/tree/main/HEADERS_proxy_connection_response