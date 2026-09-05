# Red Team Engagement Kickoff

> Adversary-emulation runbook aligned to MITRE ATT&CK and H100 tradecraft.

_Template file: `redteam_kickoff.md`_

## Pre-engagement

- Confirm purple-team agreement: detection telemetry shared, no destructive TTPs.
- Receive crown-jewel list, network architecture diagram, EDR vendor, SIEM platform.
- Set up dedicated C2 infrastructure (separate domain, frontable VPS).
- Define the rules-of-engagement: working hours, kill-switch process, panic protocol.
- Align on a single objective (data exfil, ransomware simulation) per campaign.

## Recon

- OSINT on the target organization, executives, vendors, recent breaches.
- Credential harvesting: pastebin, github, hunter.io; harvest AWS/GCP/Azure keys.
- External attack surface mapping with Shodan, Censys, and InternetDB.
- Phishing pretext design: LinkedIn scrape, conference speakers, internal lingo.
- Identify exposed VPN concentrators, RDP, SSH, and admin portals.

## Initial Access

- Phishing: 3 payloads (ISO, LNK, HTML smuggling), 50 targets per wave.
- External-facing vulnerabilities in VPN, firewall, email gateway, perimeter services.
- Valid account abuse from harvested credentials.
- Supply-chain compromise via managed-service vendor.
- Wireless proximity attack if physical access is in scope.

## Post-Exploitation

- AD enumeration: BloodHound, kerbrute, AS-REP roasting, Kerberoasting.
- Pivot to cloud via stolen refresh tokens or assumed-role credentials.
- Lateral movement via PsExec, WMI, WinRM, scheduled tasks.
- Establish persistence: registry run keys, scheduled tasks, services.
- Goal-oriented actions on objectives only — no scope creep.

## Reporting

- ATT&CK navigator layer documenting each technique observed.
- Detection gap analysis per technique: logged, alerted, blocked.
- Recommendations prioritized by detection visibility, not by severity alone.
- Final report with purple-team retest plan and timeline.

## Outputs

- `findings/*.yaml` — registered findings with severity and reproducer.
- `state/engagement/<id>/` — daily notes, surface map, evidence.
- `report/final.md` — final report delivered to the customer.
- `report/citations.md` — auto-generated methodology citations.

## Acceptance Criteria

- All findings reproducible from the documented evidence.
- Severity calibrated to the customer's business context.
- Every finding has at least one fix recommendation.
- Methodology citations attached via CitationEngine.
- Daily standups held; deviations from the runbook documented.
