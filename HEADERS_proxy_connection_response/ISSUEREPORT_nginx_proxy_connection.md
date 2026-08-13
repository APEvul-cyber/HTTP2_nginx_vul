# HTTP/2: `proxy-connection` is accepted and forwarded to the H1 backend

RFC 9113 §8.2.2: `proxy-connection` MUST NOT appear in HTTP/2. nginx already rejects `connection` / `transfer-encoding` / `upgrade` here; `proxy-connection` is missing from that list.

The header is forwarded verbatim on `proxy_pass`.

## Reproduce

HTTP/2 HEADERS with `proxy-connection: keep-alive`. Backend log shows the header. See `poc.py`.

**Actual:** forwarded.  
**Expected:** `RST_STREAM` (`PROTOCOL_ERROR`).

Related: trac #915 / #2078.

https://github.com/APEvul-cyber/HTTP2_nginx_vul/tree/main/HEADERS_proxy_connection_response