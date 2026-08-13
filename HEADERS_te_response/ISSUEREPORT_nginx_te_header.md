# HTTP/2: `te` values other than "trailers" are not rejected

RFC 9113 §8.2.2: HTTP/2 `te` MUST be `"trailers"` only.

nginx accepts `te: chunked` / `te: trailers, chunked` and proxies the request. `te` is stripped on H2→H1.

HAProxy rejects the same request. A 2017 nginx-devel patch (Piotr Sikora) already did this check and was not merged:
http://nginx.org/pipermail/nginx-devel/2017-June/010113.html

Not a live smuggling path unless `TE` is explicitly forwarded (`proxy_set_header TE $http_te`).

## Reproduce

HTTP/2 HEADERS with `te: trailers, chunked` plus a short DATA frame. See `poc.py`.

**Actual:** 200 / backend response.  
**Expected:** `RST_STREAM` (`PROTOCOL_ERROR`).

https://github.com/APEvul-cyber/HTTP2_nginx_vul/tree/main/HEADERS_te_response