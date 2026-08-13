# HTTP2_nginx_vul

PoC and reports for nginx HTTP/2.

| Dir | Issue |
|---|---|
| `HEADERS_te_response` | HTTP/2 accepts `te` values other than `trailers` (RFC 9113 §8.2.2) |
| `HEADERS_proxy_connection_response` | `proxy-connection` accepted and forwarded to the H1 backend |