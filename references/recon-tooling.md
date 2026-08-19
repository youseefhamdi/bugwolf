# Recon Tooling Catalog

> Canonical catalog of external recon tooling, organized by phase. One **PRIMARY** tool per phase is the default; **alternatives** fill gaps or replace it when an API key / install is unavailable. Install commands are for the primary tools only — long-tail alternatives are listed without a repo URL to avoid bit-rot. Tools already wired into `tools/recon_engine.sh` are marked ⚙️.

**Convention:** recon is a *pipeline*, not a grab-bag. Each phase feeds the next: `subdomains → permutations → resolve → live → port → vhost → crawl → JS → params → takeover → scan → secrets`. Run the PRIMARY of every phase; skip a phase only when its input is empty.

**Wordlists/payloads are never static:** any phase that needs one (vhost, params, dirs, payloads) generates a target-specific list via `tools/wordlist_gen.py --target T --mode <...> --research` — mine the target surface, derive wordforms, apply the tech stack, research the internet.

---

## 1. Subdomain Enumeration (passive)

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `subfinder` ⚙️ | PRIMARY — passive OSINT | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | some sources | ProjectDiscovery; the baseline |
| `assetfinder` ⚙️ | passive OSINT | `go install github.com/tomnomnom/assetfinder@latest` | — | fast, complements subfinder |
| `bbot` | PRIMARY — all-in-one OSINT + crawler | `pip install bbot` | — | enumerates + fingerprints + crawls in one pass |
| `subdog` | entropy/GitHub/API subdomain mining | `go install github.com/si9int/subdog@latest` | GitHub/API | finds subs from GitHub + certs + APIs |
| `findomain` | fast DNS + SOV | `cargo install findomain` (or release binary) | — | very fast resolution + takeover flag |
| `crt.sh` ⚙️ | certificate transparency (raw) | built-in `curl` | — | the CT source every CT tool wraps |
| `cero` | CT search | `go install github.com/glebarez/cero@latest` | — | crt.sh + more, clean output |
| `subwiz` | CT search | `go install github.com/v4d1/subwiz@latest` | — | subdomain discovery via multiple sources |
| `csprecon` | CSP-based discovery | `go install github.com/edoardottt/csprecon@latest` | — | extracts subdomains from Content-Security-Policy |
| `cspfinder` | CSP-based discovery | — | — | alt to csprecon |
| `jsubfinder` | JS-based subdomain discovery | `go install github.com/ThreatUnkown/jsubfinder@latest` | — | subs + secrets from JS |
| `chaos` ⚙️ | ProjectDiscovery DNS dataset | (built into subfinder) | `CHAOS_API_KEY` | passive dataset API |
| `haktrails` | SecurityTrails | `pip install haktrails` | SecurityTrails | API-key required |
| `shosubgo` | Shodan subdomains | `go install github.com/incogbyte/shosubgo@latest` | Shodan | API-key required |
| `github-subdomains` | GitHub code search | `go install github.com/gwen001/github-subdomains@latest` | GitHub | finds subs in org repos |

**Alt (niche/API):** `xsubfind3r`, `spk` (SparkPost), `analyticsrelationships` (Google Analytics), `udon`, `builtwithsubs`, `whoxysubs` (WhoXML), `org2asn`/`ipfinder`/`arinrange` (org→ASN→IP ranges), `haktrailsfree`.

## 2. Subdomain Permutations + Bruteforce

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `alterx` | PRIMARY — permutation engine | `go install github.com/projectdiscovery/alterx/cmd/alterx@latest` | — | pattern-based word mutations |
| `puredns` | PRIMARY — brute + resolve + wildcard filter | `go install github.com/d3mondev/puredns/v2@latest` | — | mass-resolve with wildcard/massdns |
| `dnsgen` | permutation/wordlist generation | `pip install dnsgen` | — | smart wordlist generation |
| `gotator` | permutation generator | `go install github.com/Josue87/gotator@latest` | — | number/word substitution |
| `ripgen` | permutation generator | `go install github.com/ameenmaali/ripgen@latest` | — | fast permutations |
| `shuffledns` | mass resolve + brute | `go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest` | — | alt to puredns |
| `massdns` | raw mass resolver | `git clone https://github.com/blechschmidt/massdns && make` | — | C; the engine puredns/shuffledns wrap |
| `altdns`, `goaltdns`, `dmut` | alt permutation gens | — | — | alternatives |

**Flow:** `subs → alterx + dnsgen → puredns -r resolvers.txt → new subs → back to phase 3 resolve`.

## 3. Resolution & DNS

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `dnsx` ⚙️ | PRIMARY — DNS toolkit | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` | — | A/CNAME/status, takeover-ready output |
| `puredns` | mass resolve + wildcard filter | see §2 | — | use when volume is high |
| `massdns` | raw mass resolver | see §2 | — | when puredns unavailable |
| `dig` ⚙️ | zone transfer + manual | built-in | — | `dig axfr @ns target` for zone-transfer check |

## 4. Port Scanning

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `naabu` | PRIMARY — fast SYN scan | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` | — | top-ports, fast; feeds nuclei/httpx |
| `rustscan` | very fast TCP | `cargo install rustscan` (or Docker) | — | 3s full port scan |
| `masscan` | internet-scale | `apt install masscan` | — | heavy; needs root |
| `nmap` ⚙️ | service version + NSE | `apt install nmap` | — | `-sV` on naabu output |

## 5. Probing / Live Hosts

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `httpx` ⚙️ | PRIMARY — HTTP probe + tech detect + screenshot | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | — | `-status-code -tech-detect -title -screenshot` |

## 6. VHOST Discovery

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `ffuf` ⚙️ | PRIMARY — vhost + dir fuzz | `go install github.com/ffuf/ffuf/v2@latest` | — | `-H "Host: FUZZ.target.com" -fs <size>` |
| `httpx` | vhost probing | see §5 | — | batch vhost check |

## 7. Screenshots

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `gowitness` | PRIMARY — screenshots | `go install github.com/sensepost/gowitness@latest` | — | HTML report, hashes |
| `httpx` ⚙️ | screenshots inline | see §5 | — | `-screenshot` flag |

## 8. Directory / File Enumeration

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `feroxbuster` | PRIMARY — recursive dir enum | `cargo install feroxbuster` (or release binary) | — | fast, recursive, filters |
| `dirsearch` | dir/file brute | `pip install dirsearch` | — | classic; good fallback |
| `ffuf` ⚙️ | dir/vhost/param fuzz | see §6 | — | one tool for many fuzz jobs |
| `indextree` | directory index tree enum | `go install github.com/rix4uni/indextree@latest` | — | maps a site's directory structure via its index pages |

## 9. URL Crawling & Historical

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `katana` ⚙️ | PRIMARY — active crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | — | JS-aware crawling |
| `waybackurls` ⚙️ | Wayback Machine | `go install github.com/tomnomnom/waybackurls@latest` | — | historical URLs |
| `gau` ⚙️ | Wayback + CommonCrawl + OTX | `go install github.com/lc/gau/v2/cmd/gau@latest` | — | aggregated archive |
| `waymore` | deeper archive dumps | `pip install waymore` | — | Wayback + CC + AlienVault |
| `hakrawler` | lightweight crawler | `go install github.com/hakluke/hakrawler@latest` | — | depth + forms |
| `gospider` | fast crawler + JS | `go install github.com/jaeles-project/gospider@latest` | — | JS links extraction |
| `uforall` | multi-source URL | `go install github.com/ShubhamRasal/uforall@latest` | — | combines several sources |
| `cariddi` | crawl → endpoints/secrets | `go install github.com/edoardottt/cariddi/cmd/cariddi@latest` | — | flags secrets + endpoints |
| `xurlfind3r` | multi-source URL | `go install github.com/hueristiq/xurlfind3r/cmd/xurlfind3r@latest` | — | hueristiq toolchain |
| `github-endpoints` | GitHub code search | `go install github.com/gwen001/github-endpoints@latest` | GitHub | endpoints from repos |
| `roboxtractor` | robots.txt | `go install github.com/Josue87/roboxtractor@latest` | — | extract paths from robots |
| `robotxt` | robots.txt | — | — | alt |
| `goswagger` | Swagger/OpenAPI → endpoints | `go install github.com/rix4uni/goswagger@latest` | — | extract every endpoint + param from swagger.json/openapi.json |

**Alt:** `xcrawl3r`, `crawley`, `GoLinkFinder`, `galer`, `gourlex`, `pathfinder`, `pathcrawler`.

## 10. JavaScript Crawling & Analysis

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `jsluice` | PRIMARY — JS analysis (URLs/secrets) | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` | — | the most thorough JS extractor |
| `subjs` | JS file discovery | `go install github.com/lc/subjs@latest` | — | find JS from URLs |
| `getJS` | JS file discovery | `go install github.com/003random/getJS@latest` | — | find JS from pages |
| `linkfinder` | endpoints in JS | `pip install linkfinder` | — | regex-based endpoint extraction |
| `xnLinkFinder` | endpoints + params in JS | `pip install xnLinkFinder` | — | modern LinkFinder rewrite |
| `sourcemapper` | reconstruct source from sourcemaps | `npm i -g sourcemapper` | — | `.map` → source |
| `linx` | link extractor | `go install github.com/riza/linx@latest` | — | endpoints + params |

**Alt:** `jsfinder`, `jscrawler`, `mantra`.

## 11. Hidden Parameter Discovery

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `x8` | PRIMARY — hidden params | release binary (`x8`) | — | fast, smart wordlists |
| `arjun` / `msarjun` | HTTP param discovery | `pip install arjun` | — | classic; msarjun is the maintained fork |
| `paramfinder` | param mining | `pip install paramfinder` | — | alt |

## 12. Email Enumeration

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `emailfinder` | PRIMARY — email hunting | `pip install emailfinder` | — | Google/other sources |

## 13. Subdomain / DNS / MX Takeover

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `subzy` | PRIMARY — subdomain takeover | `go install github.com/PentestPad/subzy@latest` | — | fingerprint + takeover check |
| `nuclei` ⚙️ | takeover templates | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | — | `-t http/takeovers` |
| `dnstake` | dangling DNS records | `go install github.com/pwnesia/dnstake/cmd/dnstake@latest` | — | NXDOMAIN / dangling CNAME |
| `mx-takeover` | MX record takeover | `go install github.com/musana/mx-takeover@latest` | — | email domain takeover |
| `subjack` | takeover | `go install github.com/haccer/subjack@latest` | — | alt to subzy |

## 14. Google Dorking

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `gorker` | Google dork automation | `go install github.com/petercunha/gorker@latest` | — | dork → results |

## 15. Vulnerability & Secret Scanning

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `nuclei` ⚙️ | PRIMARY — template scanning | see §13 | — | the workhorse |
| `trufflehog` ⚙️ | PRIMARY — secrets | `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \| sh` | — | git/history/filesystem |
| `s3scanner` | S3 bucket scan | `pip install s3scanner` (or `go install github.com/sa7mon/s3scanner@latest`) | — | bucket enum + perms |
| `commix` | command injection | `pip install commix` | — | OS command injection |
| `gosqli` | SQLi | `go install github.com/sqlmapproject/...` (check upstream) | — | lightweight SQLi |
| `xsschecker` / `pyxss` | XSS | `pip install pyxss` | — | XSS detection |
| `shortscan` | IIS short-name | `go install github.com/bitquark/shortscan/cmd/shortscan@latest` | — | IIS 8.3 name enum |
| `brutespray` | cred brute from nmap | `pip install brutespray` | — | takes nmap XML → hydra |
| `goop` | Google dork secrets | `go install github.com/deletescape/goop@latest` | — | dork + leak scan |
| `pvreplace` | prototype pollution | `go install github.com/...` (check upstream) | — | prototype pollution detection |
| `afrog` | fast PoC scanner (nuclei alt) | `go install github.com/zan8in/afrog/v2/cmd/afrog@latest` | — | broad PoC DB; good second opinion to nuclei |
| `ghauri` | SQLi detection + exploitation | `pip install ghauri` | — | modern SQLmap successor |
| `xssrecon` | XSS from URLs | `go install github.com/rix4uni/xssrecon@latest` | — | tests reflected/stored XSS on a URL list |
| `redirectfinder` | open redirect finder | `go install github.com/rix4uni/redirectfinder@latest` | — | detects open redirects via common params |

**Alt:** `ftpx` (FTP), `vulntechfinder`, `linkinspector`, `mantra`.

---

## 17. Resources & Wordlists

| Repo | What it feeds | Get it |
|---|---|---|
| `rix4uni/resolvers` | curated public DNS resolvers → `puredns`/`shuffledns`/`massdns` | `curl -sL https://raw.githubusercontent.com/rix4uni/resolvers/main/resolvers.txt -o wordlists/resolvers.txt` |
| `rix4uni/fresh-proxy-list` | rotating proxies → `tools/opsec.py` `FreshProxyPool` (auto-fetches `proxylist.json`) | `git clone https://github.com/rix4uni/fresh-proxy-list.git` |
| `rix4uni/wordpress-plugins` | WP plugin/slug wordlist → `ffuf`/`wpscan`/dir enum | `git clone https://github.com/rix4uni/wordpress-plugins.git wordlists/` |
| `rix4uni/cvemapping` | CVE ↔ product/version mapping → R2 `post-recon` exact-version lookup | `git clone https://github.com/rix4uni/cvemapping.git` |
| `projectdiscovery/nuclei-templates` | nuclei templates | `nuclei -update-templates` (or clone the repo) |
| `danielmiessler/seclists` | the standard wordlist set | `git clone https://github.com/danielmiessler/seclists.git wordlists/seclists` |

**Usage:** `wordlists/` holds only `resolvers.txt` (public DNS — infrastructure, not a wordlist). **No static wordlists/payloads ship:** vhost/param/directory wordlists are generated per-target by `tools/wordlist_gen.py --target T --mode <...> --research` (mines the target surface, derives wordforms, applies tech patterns, researches the internet). `cvemapping` feeds the R2 `post-recon` checkpoint (`research_loop.py`) for exact-version CVE research.

## Install One-Liner (primary set)

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/sensepost/gowitness@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/lc/subjs@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/PentestPad/subzy@latest
pip install bbot dnsgen waymore arjun emailfinder s3scanner
```

> **Rule:** `recon_engine.sh` runs the PRIMARY of every phase with a `command -v` guard and a built-in fallback, so a missing tool degrades to the next option instead of failing the pipeline. See `tools/recon_engine.sh` for the wired order.
