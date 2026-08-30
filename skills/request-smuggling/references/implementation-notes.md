# Implementation notes

Review CDN/load-balancer/gateway/origin versions and protocol transitions, duplicate header handling, hop-by-hop stripping, TE normalization, H2 request translation, and backend connection pooling. Static source of one parser is insufficient; deployment topology matters. Prefer vendor-maintained fixes and configuration guidance over custom regex normalization.
