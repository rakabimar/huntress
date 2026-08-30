# Recon tool capabilities

`./harness recon detect` checks actual local binaries and versions. Missing
optional tools are warnings. The harness never downloads tools and never
accepts model-provided flags. `./harness recon install-guide` prints maintained
upstream installation references.

| Tool | Use | Profile | Safe behavior |
|---|---|---|---|
| subfinder | passive hosts | passive+ | silent, bounded duration |
| assetfinder | passive hosts | passive+ | subs-only |
| amass | passive hosts | passive+ | passive mode, bounded timeout |
| dnsx | DNS records | light+ | JSON, A/AAAA/CNAME, bounded rate |
| ProjectDiscovery httpx | HTTP/TLS/tech | light+ | JSON, fixed observations, ROE rate/concurrency |
| gau, waybackurls | historical URLs | standard+ | multiple sources, values removed on normalization |
| katana | bounded crawl/JS URLs | standard+ | depth 2, exact-host scope, mutation-like route exclusions, low ROE bounds |
| nuclei | scanner observations | deep | tech/exposure/misconfig tags only; excludes CVE/intrusive/dos/fuzz/headless; Lead only |
| ffuf | targeted content | deep | eight-entry bundled wordlist, one base, 60-second cap |
| naabu | common ports | deep | top 100 only, bounded rate/retries |
| nmap | discovered-service detail | deep | at most ten discovered services, version-light |

The `httpx` detector rejects the Python HTTPX CLI: capability is available only
when version output identifies ProjectDiscovery httpx. Active bulk HTTP tools
are disabled when mandatory headers cannot be injected without moving secret
values outside the Broker seam.
