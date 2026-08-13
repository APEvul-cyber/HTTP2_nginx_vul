# nginx HTTP/2 accepts illegal `te` header values

**Affected:** nginx `ngx_http_v2_module` (`nginx:latest` 1.27 / 1.29, `http2 on`).  
**CWE:** CWE-20

RFC 9113 §8.2.2: if `te` is present in an HTTP/2 request, it MUST be exactly `"trailers"`. Other values MUST be treated as malformed (`PROTOCOL_ERROR`) and MUST NOT be forwarded.

nginx accepts `te: chunked` and `te: trailers, chunked` with no stream error. The request is proxied; `te` is stripped on H2→H1.

Piotr Sikora posted a patch for this on nginx-devel (2017-06-13). It was not merged.

**Impact:** H2-layer rejection is missing. Default `proxy_pass` strips `te`, so this is not a working smuggling path unless `proxy_set_header TE $http_te;` (or equivalent) is set.

## Reproduce

```
:method = POST
:scheme = https
:path = /test
:authority = target
content-length = 4
te = trailers, chunked
```

Then a 4-byte DATA frame with `END_STREAM`.

**Actual:** normal H2 response. No `RST_STREAM`.  
**Expected:** `RST_STREAM` (`PROTOCOL_ERROR`).

See `poc.py`.

## Fix

In `ngx_http_process_te`, for HTTP/2 streams accept only `"trailers"`. Otherwise return an error and do not proxy.

## References

- RFC 9113 §8.2.2, §8.1.1
- http://nginx.org/pipermail/nginx-devel/2017-June/010113.html
- CVE-2025-4600
- https://github.com/APEvul-cyber/HTTP2_nginx_vul/tree/main/HEADERS_te_response