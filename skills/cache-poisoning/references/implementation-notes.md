# Implementation notes

Review CDN and application cache policies together: query allowlists, header forwarding/key inclusion, surrogate keys, framework page/data caches, reverse proxy normalization, and authenticated bypass. Source code alone cannot prove deployed cache behavior; runtime cache headers and repeated clean requests are essential.
