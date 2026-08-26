#!/usr/bin/env python3
"""Offline defensive detection analysis for BugWolf.

The module consumes operator-supplied logs or exports. It does not collect
telemetry, execute LOLBAS commands, dump memory, access credentials, query
AD, or move laterally. Results are detection hypotheses requiring analyst
validation and environment-specific tuning.

Usage:
  python3 tools/defensive_detection.py --path exported-security.log --rules --output-dir defensive-review
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


@dataclass
class DetectionHypothesis:
    hypothesis_id: str
    category: str
    title: str
    source: str
    line_number: int
    severity: str
    rationale: str
    evidence_hash: str
    validation_questions: List[str] = field(default_factory=list)
    status: str = "analyst_review_required"


@dataclass
class DetectionRulePlan:
    rule_id: str
    category: str
    title: str
    log_sources: List[str]
    match_patterns: List[str]
    false_positive_notes: List[str]
    response: List[str]
    status: str = "plan_only"


_RULES: Sequence[tuple[str, str, str, str, str, Sequence[str], Sequence[str]]] = (
    (r"(?i)(impossible travel|new geo|unusual.*(host|source)|logon type\s*10)", "anomalous_login", "Unusual login context", "medium", "Login context differs from the user's or service's baseline.", ["Is the source host/time expected?", "Was MFA satisfied through the expected policy?"], ["Confirm with identity and VPN logs; do not reset or challenge a user automatically."]),
    (r"(?i)(net localgroup\s+administrators|special privileges|local admin|member added)", "privilege_change", "Unexpected privilege assignment", "high", "A user or process may have changed local or domain privilege membership.", ["Was there an approved change ticket?", "Which identity and host performed the change?"], ["Preserve audit records; validate the change with the system owner."]),
    (r"(?i)(powershell|pwsh).*(encodedcommand|frombase64string|invoke-expression|downloadstring|-nop|-w\s+hidden)", "script_abuse", "Suspicious PowerShell or scripting pattern", "high", "Script execution contains obfuscation, remote retrieval, or hidden execution indicators.", ["Is the parent process and signer expected?", "Does the decoded content exist in an approved change?"], ["Collect command-line telemetry and isolate only under IR procedure; do not execute the content."]),
    (r"(?i)(wmic|win32_process|wmi).*(create|call|remote|process)", "remote_wmi", "Remote WMI execution indicator", "high", "WMI appears to be used for remote process or management activity.", ["Is the source host an approved management system?", "What account and target host were involved?"], ["Correlate WMI, process, and network telemetry; do not replay the command."]),
    (r"(?i)(sc\.exe\s+.*create|service.*(created|installed)|eventid\s*7045)", "remote_service", "Unexpected service installation", "high", "A service creation or modification may indicate persistence or remote execution.", ["Was the service created in a maintenance window?", "Is the binary path signed and approved?"], ["Quarantine and investigate according to IR policy; do not delete evidence."]),
    (r"(?i)(rdp|remote interactive|logontype\s*[:=]\s*10|mstsc)", "rdp_activity", "Unusual RDP activity", "medium", "Remote interactive access may cross a normal user-to-host boundary.", ["Is the source workstation expected for this user?", "Was the destination an administrative asset?"], ["Compare with identity, VPN, and network-flow baselines."]),
    (r"(?i)(\\\\[^\s]+\\(c\$|admin\$|ipc\$)|net use|smb|445)", "smb_share", "Unexpected SMB or administrative-share access", "medium", "Administrative shares or SMB traffic may indicate tool transfer or lateral access.", ["Is this source-to-destination pair normal?", "Was sensitive data accessed or transferred?"], ["Review file-share audit and flow logs; avoid opening collected files."]),
    (r"(?i)(schtasks|scheduled task|runonce|registry\\.*(run|runonce))", "persistence_change", "Scheduled task or startup persistence indicator", "high", "A persistence-capable task or registry location appears in telemetry.", ["Is the task signed, documented, and inside a maintenance window?", "What created the task?"], ["Capture the task definition and owner; do not execute or remove it automatically."]),
    (r"(?i)(certutil|mshta|regsvr32|rundll32|bitsadmin|installutil|msbuild|mavinject|forfiles)\.exe", "lolbin", "Native signed binary abuse indicator", "medium", "A LOLBin appears in a context that may differ from normal administrative use.", ["Is the parent-child chain expected?", "Does the command access remote content or unusual paths?"], ["Tune a detection rule and investigate the full process tree; do not run the command."]),
    (r"(?i)(dns).*(query|tunnel|length|spike)|subdomain.{0,20}(length|entropy)", "dns_anomaly", "Abnormal DNS behavior", "medium", "DNS volume, length, or destination may indicate tunneling or unusual discovery.", ["What is the host baseline?", "Is the destination newly observed or approved?"], ["Correlate DNS with process and flow telemetry; do not resolve suspicious domains from the analyzer."]),
    (r"(?i)(ldap|bloodhound|sharphound|domain enumeration|directory enumeration)", "directory_enumeration", "Unusual directory-service enumeration", "medium", "A non-administrative context may be enumerating identity or host relationships.", ["Is the source a known identity-management or audit host?", "Did activity begin after a suspicious login?"], ["Review LDAP query volume and source identity; do not collect additional directory data automatically."]),
    (r"(?i)(connection|flow).*(445|3389)|workstation.{0,20}(workstation|peer)", "interhost_traffic", "Unexpected peer-to-peer traffic", "medium", "Network communication may cross a boundary not represented in the normal topology.", ["Is this protocol and direction normal for the asset role?", "Is the connection correlated with a new process?"], ["Use existing Zeek/NetFlow/Arkime records and preserve timestamps."]),
    (r"(?i)(wmi.*subscription|event subscription|5860|5861)", "wmi_persistence", "WMI event subscription indicator", "high", "A persistent WMI event subscription may execute code on a trigger.", ["Was the subscription approved and documented?", "Which namespace, consumer, and creator are involved?"], ["Escalate to incident response; do not trigger or delete the subscription automatically."]),
    (r"(?i)(process injection|virtualalloc|createremotethread|rundll32|regsvr32).*(memory|remote|inject)", "process_injection", "Possible process injection or in-memory execution", "high", "Process telemetry contains indicators associated with in-memory execution.", ["Do EDR/Sysmon parent-child and image-load records corroborate it?", "Is the binary signed and expected?"], ["Acquire memory only under approved IR procedure; do not dump credential processes automatically."]),
    (r"(?i)(rare.*(country|ip)|outbound|exfil|large transfer|arkime|zeek)", "network_anomaly", "Unusual outbound or transfer behavior", "medium", "Network telemetry suggests a rare destination or unexpected data volume.", ["What is the historical baseline?", "Is the destination business-approved?"], ["Correlate with proxy, DNS, endpoint, and asset-owner records."]),
    (r"(?i)(CurrentVersion.*Run|RunOnce|AppInit_DLLs|startup folder)", "persistence_runkey", "Registry run-key or startup-folder persistence", "high", "A run-key, RunOnce, or startup-folder reference may indicate persistence through reboot.", ["Is the entry signed, documented, and expected?", "Which account and host created it?"], ["Capture the value and owner; do not execute or remove it automatically."]),
    (r"(?i)(Image File Execution Options|IFEO|Debugger\s*=|COM\s+.*hijack|DLL\s+(?:search|hijack|planting|side.?loading))", "persistence_hijack", "DLL/COM/IFEO hijack persistence indicator", "high", "Image-file, DLL, or COM hijacking references may indicate a persistence or execution proxy.", ["Is the binary path, COM object, or debugger value documented?", "Was the change made in a maintenance window?"], ["Preserve registry and file evidence; do not run or repair the hijacked component automatically."]),
    (r"(?i)(AdminSDHolder|DSRM|Directory Services Restore|SIDHistory|DCShadow|golden ticket)", "persistence_ad", "Active Directory persistence or attack indicator", "high", "Directory-service persistence techniques appear in telemetry or rule output.", ["Is the activity from an approved admin or audit host?", "Did it follow an unusual login or privilege change?"], ["Escalate to identity/IR; do not query or modify the directory automatically."]),
    (r"(?i)(Attack Surface Reduction|ASR\s*(?:rule|policy)|BlockCredentialStealing)", "edr_asr", "ASR policy or reduction-rule reference", "medium", "An Attack Surface Reduction rule or policy reference appears, possibly indicating a disabled or bypassed control.", ["Is the rule enabled and its exclusion list reviewed?", "Did the reference come from a security-control configuration or a detection artifact?"], ["Review control posture with the security owner; do not change or disable rules automatically."]),
    (r"(?i)(Event Tracing for Windows|EtwEventWrite|NtTraceEvent|ETW\s+(?:patch|hook|bypass))", "edr_etw", "ETW telemetry or tampering reference", "medium", "ETW-related terms may indicate telemetry activity or an attempt to blind instrumentation.", ["Is this a provider/event definition or a tampering artifact?", "Does it correlate with a suspicious process tree?"], ["Correlate with endpoint/EDR telemetry; do not modify ETW providers."]),
    (r"(?i)(AmsiScanBuffer|AmsiInitialize|AMSI\s*(?:bypass|patch|init)|antimalware scan interface)", "edr_amsi", "AMSI interaction or bypass reference", "high", "AMSI-related terms may indicate script-content inspection or an attempt to evade it.", ["Does the artifact show scanning or a patch/bypass attempt?", "Which process and parent chain are involved?"], ["Treat as a detection signal; do not execute or reproduce the technique."]),
    (r"(?i)(BYOVD|vulnerable driver|driver\s+(?:load|signature)|direct syscall|syscall\s+stub|ntdll)", "edr_driver", "Driver or syscall-level evasion reference", "high", "Kernel/driver or syscall terms may indicate evasion or in-memory execution beyond user-mode visibility.", ["Is the driver signed and expected?", "Is there corroborating process, module-load, or memory telemetry?"], ["Acquire memory or driver evidence only under approved IR procedure; do not load the driver."]),
    (r"(?i)(sigma\s+rule|logsource\s*:|attack\.t\d{4}|detection\s+:) ", "sigma_rule", "Sigma detection-rule artifact", "medium", "A Sigma rule artifact indicates structured detection content that should be validated against the environment.", ["Is this a rule definition or a match/alert?", "Does it map to an existing security-control coverage gap?"], ["Use as a tuning and gap-analysis input; do not execute rule logic automatically."]),
    # ---- In-memory execution / shellcode-runner detection signals ---------
    # Detection-only taxonomy derived from a shellcode-runner case review: the
    # indicators an endpoint agent scored (MEM_PRIVATE, RW->RX transition,
    # write to private memory, thread start outside a loaded module, entropy,
    # unsigned process, import-table artifacts) and the technique variants the
    # case used to dodge them (file-mapped execution, dynamic resolution). All
    # of these are hypotheses an analyst validates against real telemetry;
    # nothing here constructs, builds, or executes an evasion primitive.
    (r"(?i)(MEM_PRIVATE|private_memory_allocation|private\s+memory.{0,30}alloc)|(VirtualAlloc|NtAllocateVirtualMemory).{0,40}(PAGE_READWRITE|private)", "memory_private_alloc", "Private memory allocation before executable content", "high", "A private (non-image) allocation may be prepared to hold executable content, the canonical shellcode-runner first step.", ["Is the process signed/expected and is this allocation part of its normal behavior?", "Does later telemetry show the region becoming executable?"], ["Correlate allocation with protection-change and thread-start events; do not dump or read the region."]),
    (r"(?i)(rw\s*(?:->|to)\s*rx|rw.?to.?rx|rw_to_rx_transition|protection_transition|memory_permission_change)|VirtualProtect.{0,40}(PAGE_EXECUTE|PAGE_READWRITE)|NtProtectVirtualMemory.{0,40}PAGE_EXECUTE", "memory_rw_rx_transition", "Writable-to-executable memory transition", "high", "A page changed from writable to executable; transitions are louder than states and are the classic allocate-write-protect pattern.", ["Does the process routinely JIT-compile or is the target module known?", "Was the executable region backed by a loaded image?"], ["Retain the transition record with process/parent context; do not invoke or reproduce the region."]),
    (r"(?i)(write_to_private_memory|RtlMoveMemory|memcpy).{0,50}(private|PAGE_EXECUTE|executable|shellcode|code)|write.{0,30}executable.{0,30}(region|memory|private)", "memory_write_executable", "Write into private/executable memory", "high", "A copy primitive wrote content into a private or executable region, the shellcode staging step.", ["Is the write part of an approved loader, updater, or JIT path?", "Does the target region's provenance (mapped image vs private) match expectations?"], ["Correlate the write with the region's allocation and later execution events."]),
    (r"(?i)thread_start_outside_loaded_module|(CreateThread|NtCreateThreadEx|SetThreadContext|start_thread).{0,60}(outside|not.{0,10}backed|loaded module|private address)", "memory_thread_outside_module", "Thread start outside a loaded module", "high", "Execution began at an address not backed by a loaded image, characteristic of injected or staged code.", ["Is the start address inside a known module, heap, or JIT region?", "Does the calling thread's stack make sense for the process?"], ["Record the start address and region type for IR; do not attach to or trace the thread."]),
    (r"(?i)(entropy.{0,20}(7\.\d|high)|high.{0,20}entropy|\"entropy\"\s*:\s*7|entropy.{0,10}risk)", "memory_high_entropy", "High-entropy executable region", "medium", "Executable memory with high entropy is consistent with packed or obfuscated payload content.", ["Is the entropy measurement from a trusted agent and region-scoped?", "Does the module's normal entropy baseline differ?"], ["Treat as corroborating evidence only; do not extract or decrypt the region."]),
    (r"(?i)(CreateFileMapping|MapViewOfFile|MEM_MAPPED|image.{0,15}mapping).{0,60}(PAGE_EXECUTE|execut|run|code|view)|mapped.{0,20}(execution|image)", "memory_mapped_execution", "Mapped-file execution variant", "medium", "A file-mapped view is made executable; mapped execution avoids private-allocation indicators while still running non-image content.", ["Is the mapped file a signed, expected module?", "Was the mapping created from a temp or user-writable path?"], ["Correlate the mapping handle, file path, and view protections; do not open the mapped file."]),
    (r"(?i)(import\s+table|IAT|statically\s+import).{0,50}(CreateThread|VirtualAlloc|VirtualProtect|RtlMoveMemory)|(CreateThread|VirtualAlloc|VirtualProtect).{0,30}(import|IAT)", "memory_import_signature", "Import-table execution signature", "medium", "The binary imports the exact primitives of a minimal runner (allocate/copy/protect/thread); import tables are the first thing an agent reads.", ["Is the binary a legit loader, installer, or runtime that legitimately imports these?", "Does static analysis corroborate the behavioral telemetry?"], ["Static-verify the import set against the vendor's artifact; do not execute the binary."]),
    (r"(?i)(GetProcAddress|LdrGetProcedureAddress).{0,60}(NtCreateThreadEx|NtAllocateVirtualMemory|NtProtectVirtualMemory|NtWriteVirtualMemory|CreateThread)", "memory_dynamic_resolution", "Dynamic resolution of execution primitives", "high", "A core execution primitive is resolved at runtime instead of being imported, hiding the capability from the import table.", ["Does the process legitimately load plugins or extensions at runtime?", "Which module resolves the address and how is it used?"], ["Correlate with thread-start and memory events; do not call the resolved address."]),
    (r"(?i)(unsigned.{0,20}(binary|process|exe|artifact)|not\s+signed|Untrusted\s*:\s*High|Zone\.Identifier|Downloads\s+folder)", "memory_unsigned_delivery", "Unsigned or untrusted-origin delivery", "medium", "An unsigned binary or a download-zone origin is a delivery-hygiene indicator that precedes any memory behavior.", ["Is the binary from an approved channel and signed by the vendor?", "What was the parent process and download origin?"], ["Verify signature and provenance; do not run the artifact to confirm."]),
    (r"(?i)(xor.{0,40}(obfuscat|decod|key|payload|array)|obfuscat.{0,30}(at rest|data section|stored|static))", "memory_obfuscated_payload", "Obfuscated payload at rest", "medium", "Payload bytes are stored obfuscated (e.g. XOR) in the data section and decoded in place, lowering static entropy and hiding the raw content.", ["Does the project legitimately obfuscate strings or licenses?", "Is the decode key and routine present in the same binary?"], ["Static analysis only; do not decode or execute the obfuscated bytes."]),
    # ---- Splunk advisory-batch detection hypotheses (offline metadata) ----
    (r"(?i)(btool|config(uration)?\s+helper|SVD-2026-0614).{0,200}(command\s+injection|shell\s+(?:interpret|command)|exec\s*\(|subprocess|admin\s+role|admin\s+user|CWE-?78)", "splunk_btool_cmd", "Splunk AI Toolkit btool command-injection hypothesis (SVD-2026-0614)", "high", "Telemetry or advisory text references the Splunk btool configuration helper alongside command-string or shell-interpreter language.", ["Does the artifact mention btool with admin or untrusted input reaching a command sink?", "Which Splunk version is involved and is it below 5.7.4?"], ["Cross-reference with process-execution telemetry on the Splunk host; do not replicate or fire the btool helper."]),
    (r"(?i)(deployment\s+server|SVD-2026-0702).{0,120}(csrf|cross.site|SPL|splunk\s+user|capable\s+user)", "splunk_deployment_csrf", "Splunk Deployment Server CSRF hypothesis (SVD-2026-0702)", "high", "Telemetry or advisory text references a Deployment Server endpoint being tricked into running SPL with elevated context.", ["Is the user capable of Deployment Server actions?", "Was a state-changing SPL invoked outside the expected session?"], ["Correlate with identity, browser, and Splunk auditd logs; do not replay the cross-site chain."]),
    (r"(?i)(app\s+install|SVD-2026-0703).{0,180}(path\s+traversal|\\.\\./|outside\s+the\s+app\s+directory|write\s+files?\s+outside)", "splunk_app_install_trav", "Splunk app-install path-traversal hypothesis (SVD-2026-0703)", "high", "App-installation logic references writing files outside the application directory, path traversal patterns included, or an advisory tie-in.", ["Does the artifact point to a write that escapes the canonical app directory?", "Is the Splunk version below 10.4.1, 10.2.5, 10.0.8 or earlier?"], ["Compare Splunk file-write telemetry against the app-installation root; do not trigger a malicious install."]),
    (r"(?i)(storage/passwords|SVD-2026-0704|credential\s+hash(es)?).{0,140}(exposed|expos|endpoint|response|leak)", "splunk_storage_creds", "Splunk storage/passwords credential-hash exposure hypothesis (SVD-2026-0704)", "high", "Telemetry or advisory text references the storage/passwords endpoint or stored credential hashes being returned.", ["Is the artifact a vendor advisory, a request log, or a response body?", "Which identity would retrieve or own the given hash?"], ["Capture the relevant request and response, then rotate any credentials that could plausibly match the hash; never hash or replay stolen material."]),
)


def detection_rule_plans() -> List[DetectionRulePlan]:
    plans = []
    for index, (pattern, category, title, _, rationale, questions, response) in enumerate(_RULES, 1):
        plans.append(DetectionRulePlan(
            rule_id=f"bugwolf-detect-{index:02d}", category=category, title=title,
            log_sources=["Windows Security/Sysmon", "EDR", "Zeek/NetFlow", "identity provider", "OSQuery/Velociraptor export"],
            match_patterns=[pattern], false_positive_notes=questions,
            response=list(response),
        ))
    return plans


def analyze_artifact(text: str, source: str = "artifact") -> List[DetectionHypothesis]:
    results: List[DetectionHypothesis] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for pattern, category, title, severity, rationale, questions, response in _RULES:
            if re.search(pattern, line):
                digest = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
                hypothesis_id = hashlib.sha256(f"{source}:{line_number}:{category}:{digest}".encode()).hexdigest()[:16]
                results.append(DetectionHypothesis(
                    hypothesis_id=hypothesis_id, category=category, title=title,
                    source=source, line_number=line_number, severity=severity,
                    rationale=rationale, evidence_hash=digest,
                    validation_questions=list(questions) + list(response),
                ))
    return results


def analyze_paths(paths: Iterable[Path]) -> List[DetectionHypothesis]:
    results: List[DetectionHypothesis] = []
    for path in paths:
        if path.is_file():
            results.extend(analyze_artifact(path.read_text(encoding="utf-8", errors="replace"), str(path)))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf offline defensive detection analysis")
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--rules", action="store_true")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    hypotheses = analyze_paths(Path(path) for path in args.path)
    with (output / "detection-hypotheses.jsonl").open("w", encoding="utf-8") as handle:
        for item in hypotheses:
            handle.write(json.dumps(asdict(item), sort_keys=True) + "\n")
    if args.rules:
        with (output / "detection-rule-plans.jsonl").open("w", encoding="utf-8") as handle:
            for item in detection_rule_plans():
                handle.write(json.dumps(asdict(item), sort_keys=True) + "\n")
    manifest = {"schema": "bugwolf-defensive-detection-v1", "hypotheses": len(hypotheses),
                "rules": len(_RULES), "execution": "offline_artifacts_only"}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
