# Recon Tooling Catalog

> Canonical catalog of external recon tooling, organized by phase. One **PRIMARY** tool per phase is the default; **alternatives** fill gaps or replace it when an API key / install is unavailable. Install commands are for the primary tools only — long-tail alternatives are listed without a repo URL to avoid bit-rot. Tools already wired into `tools/recon_engine.sh` are marked ⚙️.

**Convention:** recon is a *pipeline*, not a grab-bag. Each phase feeds the next: `subdomains → permutations → resolve → live → port → vhost → crawl → JS → params → takeover → scan → secrets`. Run the PRIMARY of every phase; skip a phase only when its input is empty.

**Wordlists/payloads are never static:** any phase that needs one (vhost, params, dirs, payloads) generates a target-specific list via `tools/wordlist_gen.py --target T --mode <...> --research` — mine the target surface, derive wordforms, apply the tech stack, research the internet.

## Supply-chain policy (Phase 6 opsec — read before installing anything)

Every install command in this catalog is a supply-chain decision. Rules,
not suggestions:

1. **Tagged releases, never `@latest`/`main`.** `@latest` means "whatever
   upstream serves right now" — an upstream compromise becomes a local
   compromise the moment you install. `<release-tag>` in the install
   column = the specific tagged release you vetted for this engagement
   (each project's GitHub releases page lists them). Record the resolved
   version in the mission journal.
2. **No pipe-to-shell.** Never `curl … | sh` / `| bash`: the payload runs
   with your privileges before you ever saw it. Fetch → inspect → verify
   → run.
3. **Checksums where published.** Projects shipping `SHA256SUMS` with
   releases: download the artifact, `sha256sum -c` against it, install
   from the verified file.
4. **Pinned clones.** `git clone` for source builds must pin
   `--branch <tag> --depth 1` — a moving `main` is `@latest` with extra
   steps.
5. **Record, don't assume.** After install run the tool's `--version`
   once and journal it; a tool that silently changes version between
   missions invalidates replay baselines and provenance.

Version-pin the resolver inventory too: a resolver list fetched at
runtime from an unverified source poisons every DNS-derived artifact.
Ship static lists with the tree or pin the upstream source.

## BugWolf intelligence adapter

`tools/js_ct_intel.py` is the canonical adapter for the JS/CT category. It keeps the methodology's useful sequence—passive CT, URL collection, local JS analysis, then workflow hypotheses—without treating scanner output as a finding.

| Input/adapter | Output | Safety boundary |
|---|---|---|
| `crt.name/v1/search?apex=<target>&dates=1` | `ct-records.jsonl` with first/last-seen fields where supplied | HTTPS, response-size bound, explicit scope filter |
| `crt.sh` | fallback CT names | Same scope filter; never merged from an unauthorized sibling |
| `katana`, `hakrawler` | crawler URL inputs | Optional only; `--collect-crawlers` + `--confirm-active` |
| LinkFinder | endpoint candidates | Local JS only; unavailable means built-in extractor |
| `js-beautify` or `prettier` | beautified local copies | No source modification; local files only |
| `grep` | redacted line indicators | Secret values are replaced by hashes and lengths |

The adapter writes `ct-subdomains.txt`, `js-endpoints.txt`, `js-analysis.jsonl`, `js-secrets.jsonl`, `js-grep.jsonl`, `workflow-hypotheses.jsonl`, and `manifest.json`. Workflow categories are hypotheses for manual state-machine testing: skipped/reordered/repeated steps, role differences, payment/subscription boundaries, verification, privileged routes, and file boundaries.

`tools/methodology_playbook.py` consumes the URL and scanner artifacts after this phase. It emits `workflow-plans.jsonl`, `idor-matrix.jsonl`, `validation-tasks.jsonl`, and non-executing `tool-plans.jsonl`. `ffuf`, `nuclei`, SQLMap, and XSStrike are treated as confirmation adapters—not discovery verdicts. The default plan is offline-only; SQLMap plans exclude database enumeration and dumping.

`tools/asset_intel.py` handles the broader passive-source category. It normalizes supplied Amass/Shodan/Censys/FOFA/ZoomEye/SpiderFoot exports and emits provider query plans without contacting those services. `tools/defensive_detection.py` is for supplied host/network logs; it does not collect telemetry or execute LOLBins.

---

## 1. Subdomain Enumeration (passive)

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `subfinder` ⚙️ | PRIMARY — passive OSINT | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@<release-tag>` | some sources | ProjectDiscovery; the baseline |
| `assetfinder` ⚙️ | passive OSINT | `go install github.com/tomnomnom/assetfinder@<release-tag>` | — | fast, complements subfinder |
| `bbot` | PRIMARY — all-in-one OSINT + crawler | `pip install bbot==<pinned-version>` | — | enumerates + fingerprints + crawls in one pass |
| `subdog` | entropy/GitHub/API subdomain mining | `go install github.com/si9int/subdog@<release-tag>` | GitHub/API | finds subs from GitHub + certs + APIs |
| `findomain` | fast DNS + SOV | `cargo install findomain@<version>` (or verified release binary) | — | very fast resolution + takeover flag |
| `crt.sh` ⚙️ | certificate transparency (raw) | built-in `curl` | — | the CT source every CT tool wraps |
| `cero` | CT search | `go install github.com/glebarez/cero@<release-tag>` | — | crt.sh + more, clean output |
| `subwiz` | CT search | `go install github.com/v4d1/subwiz@<release-tag>` | — | subdomain discovery via multiple sources |
| `csprecon` | CSP-based discovery | `go install github.com/edoardottt/csprecon@<release-tag>` | — | extracts subdomains from Content-Security-Policy |
| `cspfinder` | CSP-based discovery | — | — | alt to csprecon |
| `jsubfinder` | JS-based subdomain discovery | `go install github.com/ThreatUnkown/jsubfinder@<release-tag>` | — | subs + secrets from JS |
| `chaos` ⚙️ | ProjectDiscovery DNS dataset | (built into subfinder) | `CHAOS_API_KEY` | passive dataset API |
| `haktrails` | SecurityTrails | `pip install haktrails==<pinned-version>` | SecurityTrails | API-key required |
| `shosubgo` | Shodan subdomains | `go install github.com/incogbyte/shosubgo@<release-tag>` | Shodan | API-key required |
| `github-subdomains` | GitHub code search | `go install github.com/gwen001/github-subdomains@<release-tag>` | GitHub | finds subs in org repos |

**Alt (niche/API):** `xsubfind3r`, `spk` (SparkPost), `analyticsrelationships` (Google Analytics), `udon`, `builtwithsubs`, `whoxysubs` (WhoXML), `org2asn`/`ipfinder`/`arinrange` (org→ASN→IP ranges), `haktrailsfree`.

## 2. Subdomain Permutations + Bruteforce

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `alterx` | PRIMARY — permutation engine | `go install github.com/projectdiscovery/alterx/cmd/alterx@<release-tag>` | — | pattern-based word mutations |
| `puredns` | PRIMARY — brute + resolve + wildcard filter | `go install github.com/d3mondev/puredns/v2@<release-tag>` | — | mass-resolve with wildcard/massdns |
| `dnsgen` | permutation/wordlist generation | `pip install dnsgen==<pinned-version>` | — | smart wordlist generation |
| `gotator` | permutation generator | `go install github.com/Josue87/gotator@<release-tag>` | — | number/word substitution |
| `ripgen` | permutation generator | `go install github.com/ameenmaali/ripgen@<release-tag>` | — | fast permutations |
| `shuffledns` | mass resolve + brute | `go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@<release-tag>` | — | alt to puredns |
| `massdns` | raw mass resolver | `git clone --branch <tag> --depth 1 https://github.com/blechschmidt/massdns && make` | — | C; the engine puredns/shuffledns wrap |
| `altdns`, `goaltdns`, `dmut` | alt permutation gens | — | — | alternatives |

**Flow:** `subs → alterx + dnsgen → puredns -r resolvers.txt → new subs → back to phase 3 resolve`.

## 3. Resolution & DNS

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `dnsx` ⚙️ | PRIMARY — DNS toolkit | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@<release-tag>` | — | A/CNAME/status, takeover-ready output |
| `puredns` | mass resolve + wildcard filter | see §2 | — | use when volume is high |
| `massdns` | raw mass resolver | see §2 | — | when puredns unavailable |
| `dig` ⚙️ | zone transfer + manual | built-in | — | `dig axfr @ns target` for zone-transfer check |

## 4. Port Scanning

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `naabu` | PRIMARY — fast SYN scan | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@<release-tag>` | — | top-ports, fast; feeds nuclei/httpx |
| `rustscan` | very fast TCP | `cargo install rustscan` (or Docker) | — | 3s full port scan |
| `masscan` | internet-scale | `apt install masscan` | — | heavy; needs root |
| `nmap` ⚙️ | service version + NSE | `apt install nmap` | — | `-sV` on naabu output |

## 5. Probing / Live Hosts

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `httpx` ⚙️ | PRIMARY — HTTP probe + tech detect + screenshot | `go install github.com/projectdiscovery/httpx/cmd/httpx@<release-tag>` | — | `-status-code -tech-detect -title -screenshot` |

## 6. VHOST Discovery

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `ffuf` ⚙️ | PRIMARY — vhost + dir fuzz | `go install github.com/ffuf/ffuf/v2@<release-tag>` | — | `-H "Host: FUZZ.target.com" -fs <size>` |
| `httpx` | vhost probing | see §5 | — | batch vhost check |

## 7. Screenshots

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `gowitness` | PRIMARY — screenshots | `go install github.com/sensepost/gowitness@<release-tag>` | — | HTML report, hashes |
| `httpx` ⚙️ | screenshots inline | see §5 | — | `-screenshot` flag |

## 8. Directory / File Enumeration

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `feroxbuster` | PRIMARY — recursive dir enum | `cargo install feroxbuster@<version>` (or verified release binary) | — | fast, recursive, filters |
| `dirsearch` | dir/file brute | `pip install dirsearch==<pinned-version>` | — | classic; good fallback |
| `ffuf` ⚙️ | dir/vhost/param fuzz | see §6 | — | one tool for many fuzz jobs |
| `indextree` | directory index tree enum | `go install github.com/rix4uni/indextree@<release-tag>` | — | maps a site's directory structure via its index pages |

## 9. URL Crawling & Historical

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `katana` ⚙️ | PRIMARY — active crawler | `go install github.com/projectdiscovery/katana/cmd/katana@<release-tag>` | — | JS-aware crawling |
| `waybackurls` ⚙️ | Wayback Machine | `go install github.com/tomnomnom/waybackurls@<release-tag>` | — | historical URLs |
| `gau` ⚙️ | Wayback + CommonCrawl + OTX | `go install github.com/lc/gau/v2/cmd/gau@<release-tag>` | — | aggregated archive |
| `waymore` | deeper archive dumps | `pip install waymore==<pinned-version>` | — | Wayback + CC + AlienVault |
| `hakrawler` | lightweight crawler | `go install github.com/hakluke/hakrawler@<release-tag>` | — | depth + forms |
| `gospider` | fast crawler + JS | `go install github.com/jaeles-project/gospider@<release-tag>` | — | JS links extraction |
| `uforall` | multi-source URL | `go install github.com/ShubhamRasal/uforall@<release-tag>` | — | combines several sources |
| `cariddi` | crawl → endpoints/secrets | `go install github.com/edoardottt/cariddi/cmd/cariddi@<release-tag>` | — | flags secrets + endpoints |
| `xurlfind3r` | multi-source URL | `go install github.com/hueristiq/xurlfind3r/cmd/xurlfind3r@<release-tag>` | — | hueristiq toolchain |
| `github-endpoints` | GitHub code search | `go install github.com/gwen001/github-endpoints@<release-tag>` | GitHub | endpoints from repos |
| `roboxtractor` | robots.txt | `go install github.com/Josue87/roboxtractor@<release-tag>` | — | extract paths from robots |
| `robotxt` | robots.txt | — | — | alt |
| `goswagger` | Swagger/OpenAPI → endpoints | `go install github.com/rix4uni/goswagger@<release-tag>` | — | extract every endpoint + param from swagger.json/openapi.json |

**Alt:** `xcrawl3r`, `crawley`, `GoLinkFinder`, `galer`, `gourlex`, `pathfinder`, `pathcrawler`.

## 10. JavaScript Crawling & Analysis

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `jsluice` | PRIMARY — JS analysis (URLs/secrets) | `go install github.com/BishopFox/jsluice/cmd/jsluice@<release-tag>` | — | the most thorough JS extractor |
| `subjs` | JS file discovery | `go install github.com/lc/subjs@<release-tag>` | — | find JS from URLs |
| `getJS` | JS file discovery | `go install github.com/003random/getJS@<release-tag>` | — | find JS from pages |
| `linkfinder` | endpoints in JS | `pip install linkfinder==<pinned-version>` | — | regex-based endpoint extraction |
| `xnLinkFinder` | endpoints + params in JS | `pip install xnLinkFinder` | — | modern LinkFinder rewrite |
| `sourcemapper` | reconstruct source from sourcemaps | `npm i -g sourcemapper` | — | `.map` → source |
| `linx` | link extractor | `go install github.com/riza/linx@<release-tag>` | — | endpoints + params |

**Alt:** `jsfinder`, `jscrawler`, `mantra`.

## 11. Hidden Parameter Discovery

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `x8` | PRIMARY — hidden params | release binary (`x8`) | — | fast, smart wordlists |
| `arjun` / `msarjun` | HTTP param discovery | `pip install arjun==<pinned-version>` | — | classic; msarjun is the maintained fork |
| `paramfinder` | param mining | `pip install paramfinder==<pinned-version>` | — | alt |

## 12. Email Enumeration

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `emailfinder` | PRIMARY — email hunting | `pip install emailfinder==<pinned-version>` | — | Google/other sources |

## 13. Subdomain / DNS / MX Takeover

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `subzy` | PRIMARY — subdomain takeover | `go install github.com/PentestPad/subzy@<release-tag>` | — | fingerprint + takeover check |
| `nuclei` ⚙️ | takeover templates | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@<release-tag>` | — | `-t http/takeovers` |
| `dnstake` | dangling DNS records | `go install github.com/pwnesia/dnstake/cmd/dnstake@<release-tag>` | — | NXDOMAIN / dangling CNAME |
| `mx-takeover` | MX record takeover | `go install github.com/musana/mx-takeover@<release-tag>` | — | email domain takeover |
| `subjack` | takeover | `go install github.com/haccer/subjack@<release-tag>` | — | alt to subzy |

## 14. Google Dorking

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `gorker` | Google dork automation | `go install github.com/petercunha/gorker@<release-tag>` | — | dork → results |

## 15. Vulnerability & Secret Scanning

| Tool | Role | Install | Key | Note |
|---|---|---|---|---|
| `nuclei` ⚙️ | PRIMARY — template scanning | see §13 | — | the workhorse |
| `trufflehog` ⚙️ | PRIMARY — secrets | release binary from `github.com/trufflesecurity/trufflehog/releases` — verify its `sha256` against the release's checksums before installing | — | git/history/filesystem |
| `s3scanner` | S3 bucket scan | `pip install s3scanner==<pinned-version>` (or `go install github.com/sa7mon/s3scanner@<release-tag>`) | — | bucket enum + perms |
| `commix` | command injection | `pip install commix==<pinned-version>` | — | OS command injection |
| `gosqli` | SQLi | `go install github.com/sqlmapproject/...` (check upstream) | — | lightweight SQLi |
| `xsschecker` / `pyxss` | XSS | `pip install pyxss==<pinned-version>` | — | XSS detection |
| `shortscan` | IIS short-name | `go install github.com/bitquark/shortscan/cmd/shortscan@<release-tag>` | — | IIS 8.3 name enum |
| `brutespray` | cred brute from nmap | `pip install brutespray==<pinned-version>` | — | takes nmap XML → hydra |
| `goop` | Google dork secrets | `go install github.com/deletescape/goop@<release-tag>` | — | dork + leak scan |
| `pvreplace` | prototype pollution | `go install github.com/...` (check upstream) | — | prototype pollution detection |
| `afrog` | fast PoC scanner (nuclei alt) | `go install github.com/zan8in/afrog/v2/cmd/afrog@<release-tag>` | — | broad PoC DB; good second opinion to nuclei |
| `ghauri` | SQLi detection + exploitation | `pip install ghauri==<pinned-version>` | — | modern SQLmap successor |
| `xssrecon` | XSS from URLs | `go install github.com/rix4uni/xssrecon@<release-tag>` | — | tests reflected/stored XSS on a URL list |
| `redirectfinder` | open redirect finder | `go install github.com/rix4uni/redirectfinder@<release-tag>` | — | detects open redirects via common params |

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
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@<release-tag>
go install github.com/tomnomnom/assetfinder@<release-tag>
go install github.com/projectdiscovery/alterx/cmd/alterx@<release-tag>
go install github.com/d3mondev/puredns/v2@<release-tag>
go install github.com/projectdiscovery/dnsx/cmd/dnsx@<release-tag>
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@<release-tag>
go install github.com/projectdiscovery/httpx/cmd/httpx@<release-tag>
go install github.com/sensepost/gowitness@<release-tag>
go install github.com/projectdiscovery/katana/cmd/katana@<release-tag>
go install github.com/lc/gau/v2/cmd/gau@<release-tag>
go install github.com/tomnomnom/waybackurls@<release-tag>
go install github.com/BishopFox/jsluice/cmd/jsluice@<release-tag>
go install github.com/lc/subjs@<release-tag>
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@<release-tag>
go install github.com/PentestPad/subzy@<release-tag>
pip install bbot dnsgen waymore arjun emailfinder s3scanner
```

> **Rule:** `recon_engine.sh` runs the PRIMARY of every phase with a `command -v` guard and a built-in fallback, so a missing tool degrades to the next option instead of failing the pipeline. See `tools/recon_engine.sh` for the wired order.
