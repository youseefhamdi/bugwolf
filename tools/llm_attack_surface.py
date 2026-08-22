#!/usr/bin/env python3
"""
BugWolf LLM / Agentic AI Attack-Surface Detector v1.0.0

Fingerprints the LLM/RAG/agentic attack surface of a codebase or live target so
the llm-ai-agent can hunt it. Grounded in the OWASP GenAI LLM Top 10 2026 and
OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10).

Detection is deterministic (regex/static analysis) — no network is required for
`--path` scans, and every hit maps to a canonical `llm-*` bug class so findings
slot straight into the shared-rules CWE mapping.

Usage:
  python3 tools/llm_attack_surface.py --path .
  python3 tools/llm_attack_surface.py --path src --json
  python3 tools/llm_attack_surface.py --url https://target.example --json
  python3 tools/llm_attack_surface.py --path . --min-severity high
"""

import json
import re
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
    from tools.safety import AuthorizationError, require_authorized_target
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root
    from safety import AuthorizationError, require_authorized_target

ROOT = workspace_root()
sys.path.insert(0, str(CODE_ROOT))

# File extensions worth scanning (source + config). Skipping binaries/lockfiles.
SCAN_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".kt", ".swift",
    ".rb", ".php", ".cs", ".yaml", ".yml", ".json", ".toml", ".tf", ".sh",
    ".md", ".txt", ".env", ".mjs", ".cjs", ".scala", ".dart", ".ex", ".exs",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
             "build", "target", ".next", "vendor", ".idea", ".mypy_cache"}


@dataclass
class SurfaceFinding:
    bug_class: str
    severity: str  # critical | high | medium | low | informational
    owasp_llm: str  # LLM01..LLM10 or ""
    owasp_asi: str  # ASI01..ASI10 or ""
    evidence: str  # matched text (truncated)
    file: str
    line: int
    detail: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Detection rules
#
# Each rule: (bug_class, severity, owasp_llm, owasp_asi, detail, [regexes])
# Severity reflects the *presence* of a high-value surface, not a confirmed vuln.
# ---------------------------------------------------------------------------

RULES = [
    # --- Hidden context / secrets in system prompts (LLM08 / LLM02) ---
    ("hidden-context-exposure", "high", "LLM08", "",
     "System-prompt or instruction text that may embed secrets or sensitive control logic.",
     [
         r"(?i)system[_ ]?prompt\s*[=:]\s*[\"'][^\"']*(api[_-]?key|token|secret|password|BEGIN .*PRIVATE KEY)[^\"']*[\"']",
         r"(?i)(system|developer|instructions)\s*[=:].*(sk_live_|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[bp]-)",
     ]),

    # --- Prompt injection surface (LLM01) ---
    ("prompt-injection", "high", "LLM01", "ASI01",
     "Prompt is assembled from external/untrusted input (retrieved text, user content, web/email/tool output).",
     [
         r"(?i)prompt\s*[=+].*(user_input|user_query|message|content|context|retriev|search_result|email|document|web_page)",
         r"(?i)f-string.*(input|message|prompt)|template.*(input|message|prompt)",
         r"(?i)\.format\((user|input|message|query|context|content)",
         r"(?i)system_message\s*\+\s*(user|input|message|query)",
     ]),

    # --- Excessive agency / dangerous tools (LLM03 / ASI02 / ASI05) ---
    ("excessive-agency", "critical", "LLM03", "ASI02",
     "Open-ended or privileged tool available to the model (shell exec, code eval, URL fetch).",
     [
         r"(?i)\b(subprocess|os\.system|os\.popen|Popen|shell=True)\b",
         r"(?i)\b(eval\(|exec\(|Function\(|child_process\.exec|Runtime\.getRuntime\(\)\.exec)\b",
         r"(?i)(run_shell|execute_code|execute_command|shell_command|run_command|fetch_url|browse_url)",
         r"(?i)allow_dangerous|allow_code_execution|unsafe_eval|exec_tool|code_interpreter",
     ]),

    # --- Tool/function calling surface (ASI02) ---
    ("tool-misuse", "medium", "LLM03", "ASI02",
     "Tool/function-calling surface present — schemas the model may be coerced to misuse.",
     [
         r"(?i)(tool_call|function_call|tool_choice|parallel_tool_calls|register_tool|@tool|Tool\()",
         r"(?i)json_schema|parameters_schema|tool_schemas|functions\s*=\s*\[",
         r"(?i)openai\.(chat\.)?completions|anthropic\.messages|langchain|langgraph|crewai|autogen|llamaindex|semantic-kernel",
     ]),

    # --- RAG retrieval pipeline (LLM09) ---
    ("rag-poisoning", "high", "LLM09", "",
     "Retrieval-augmented pipeline — content can be poisoned to steer responses.",
     [
         r"(?i)(retriev|similarity_search|vector_search|semantic_search|rag_pipeline|knowledge_base|search_index)",
         r"(?i)(pinecone|weaviate|qdrant|chroma|milvus|pgvector|faiss|annoy|elasticsearch|opensearch)",
         r"(?i)(llamaindex|haystack|langchain_community\.vectorstores)",
     ]),

    # --- Embedding storage / export (LLM09 inversion) ---
    ("embedding-inversion", "medium", "LLM09", "",
     "Embeddings persisted/exported — treat a leak as source-document disclosure.",
     [
         r"(?i)(embedding[s]?\.(save|dump|to_json|export)|save_embeddings|embedding_backup|\.npy|\.npz|\.parquet)",
         r"(?i)(upload_embeddings|export_vectors|embedding_store|vector_backup)",
     ]),

    # --- Cross-tenant vector index (LLM09) ---
    ("cross-tenant-vector-leak", "high", "LLM09", "",
     "Shared vector index with post-retrieval tenant filtering (search runs before access control).",
     [
         r"(?i)(tenant_id|tenant_filter|namespace|partition_key|metadata_filter).*(filter|scope|where)",
         r"(?i)(multi[-_ ]?tenant|shared_index|shared_namespace|shared_collection)",
         r"(?i)similarity_search.*(filter|where|tenant|namespace)",
     ]),

    # --- Semantic cache / dedup (LLM09) ---
    ("semantic-cache-poisoning", "medium", "LLM09", "",
     "Cosine-threshold cache or dedup — attacker content can straddle the threshold.",
     [
         r"(?i)(semantic_cache|similarity_cache|dedup|deduplicate|near_duplicate|cosine_similarity\s*[<>=])",
         r"(?i)(similarity_threshold|score_threshold|cache.*embedding|embedding.*cache)",
     ]),

    # --- Agent memory (ASI06) ---
    ("memory-poisoning", "high", "LLM05", "ASI06",
     "Persistent agent memory/checkpoint store — attacker content can survive sessions.",
     [
         r"(?i)(long[_ -]?term[_ -]?memory|memory_store|persistent_memory|conversation_history|scratchpad|checkpoint|memory\.save|remember\()",
         r"(?i)(langgraph.*memory|mem0|zep|letta|memgpt|memory_agent)",
     ]),

    # --- Inter-agent communication (ASI07) ---
    ("inter-agent-comms", "medium", "", "ASI07",
     "Multi-agent message channels — check for auth/signing on inter-agent messages.",
     [
         r"(?i)(inter[-_ ]?agent|multi[-_ ]?agent|agent_bus|message_bus|agent.*broadcast|publish.*agent|agent.*subscribe)",
         r"(?i)(crewai|autogen|swarm|multiagent|agent_graph|supervisor_agent|handoff)",
     ]),

    # --- Cascading failure (ASI08) ---
    ("cascading-failure", "low", "", "ASI08",
     "Agents consume each other's output — one poisoned agent propagates.",
     [
         r"(?i)(cascad|propagat.*agent|agent.*depends.*agent|downstream_agent|orchestrat.*agent|pipeline.*agent)",
     ]),

    # --- Human-agent trust (ASI09) ---
    ("human-agent-trust", "low", "", "ASI09",
     "Agent summarizes/curates content for human approval — approval UX is influenceable.",
     [
         r"(?i)(human_in_the_loop|human_approval|approval_flow|requires_approval|await.*confirm|approval.*agent)",
     ]),

    # --- Rogue agent / sandbox escape (ASI10) ---
    ("rogue-agent", "high", "", "ASI10",
     "Agent sandbox/policy boundary — test code-exec egress and policy enforcement.",
     [
         r"(?i)(sandbox|jailbreak_detection|policy_enforcement|guardrails|agent_boundary|sandboxed_agent|untrusted_code_exec)",
     ]),

    # --- MCP servers (ASI04) ---
    ("mcp-injection", "high", "LLM04", "ASI04",
     "Model Context Protocol surface — servers/plugins are injection + SSRF + credential surfaces.",
     [
         r"(?i)(mcp_server|modelcontextprotocol|mcp__|mcp\.json|claude_desktop_config|resources://)",
         r'(?i)("mcpServers"|"mcp"|mcp_config|mcp_client|streamable_http|sse.*mcp)',
     ]),

    # --- Model DoS / unbounded consumption (LLM06) ---
    ("model-dos", "medium", "LLM06", "",
     "Unbounded token/context/tool-loop consumption surface.",
     [
         r"(?i)(max_tokens\s*=\s*None|unlimited_tokens|no_max_tokens|max_iterations\s*=\s*None)",
         r"(?i)(while\s+True.*(tool|agent|completion)|infinite_loop|retry_forever)",
     ]),

    # --- Misinformation / unvalidated output to sinks (LLM07 / LLM10) ---
    ("improper-output-handling", "high", "LLM10", "",
     "LLM output flows into a sink (SQL, shell, HTML, eval) without deterministic validation.",
     [
         r"(?i)(llm.*(sql|query|command|html|javascript|eval)|response\.content.*(execute|exec|run|query))",
         r"(?i)(model.*output|llm_output|completion).*(sql|exec|eval|render|write|query)",
     ]),
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class LLMAttackSurfaceScanner:
    """Deterministic fingerprint of LLM/agentic attack surface."""

    def __init__(self, min_severity: str = "informational"):
        order = ["informational", "low", "medium", "high", "critical"]
        self._min = order.index(min_severity) if min_severity in order else 0

    def _passes(self, severity: str) -> bool:
        order = ["informational", "low", "medium", "high", "critical"]
        return order.index(severity) >= self._min

    def scan_text(self, text: str, file: str = "<input>",
                  start_line: int = 1) -> List[SurfaceFinding]:
        """Scan a single blob of text and return matched findings."""
        findings: List[SurfaceFinding] = []
        for bug_class, severity, llm, asi, detail, patterns in RULES:
            if not self._passes(severity):
                continue
            for pat in patterns:
                for m in re.finditer(pat, text):
                    line = text.count("\n", 0, m.start()) + start_line
                    evidence = m.group(0)
                    if len(evidence) > 160:
                        evidence = evidence[:157] + "..."
                    findings.append(SurfaceFinding(
                        bug_class=bug_class,
                        severity=severity,
                        owasp_llm=llm,
                        owasp_asi=asi,
                        evidence=evidence,
                        file=file,
                        line=line,
                        detail=detail,
                    ))
        return findings

    def scan_path(self, path: str) -> List[SurfaceFinding]:
        """Recursively scan a directory or single file."""
        root = Path(path)
        findings: List[SurfaceFinding] = []
        files: List[Path] = []

        if root.is_file():
            files = [root]
        elif root.is_dir():
            for p in root.rglob("*"):
                if not p.is_file():
                    continue
                if any(part in SKIP_DIRS for part in p.parts):
                    continue
                if p.suffix.lower() in SCAN_EXTS:
                    files.append(p)
        else:
            print(f"[!] path not found: {path}", file=sys.stderr)
            return findings

        for f in sorted(files):
            try:
                text = f.read_text(errors="ignore")
            except OSError:
                continue
            findings.extend(self.scan_text(text, file=str(f)))

        return findings

    def scan_url(self, url: str, *, scope_file: Optional[str] = None) -> List[SurfaceFinding]:
        """Read-only fingerprint gated by explicit target authorization."""
        findings: List[SurfaceFinding] = []
        try:
            require_authorized_target(url, scope_file, active=False)
        except AuthorizationError as exc:
            print(f"[!] authorization denied for {url}: {exc}", file=sys.stderr)
            return findings
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "bugwolf-llm-surf/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read(4096).decode("utf-8", "ignore")
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as e:
            print(f"[!] fetch failed for {url}: {e}", file=sys.stderr)
            return findings

        markers = {
            "x-powered-by": "server fingerprint",
            "server": "server fingerprint",
        }
        for hdr, label in markers.items():
            if hdr in headers:
                findings.append(SurfaceFinding(
                    bug_class="info-disclosure", severity="informational",
                    owasp_llm="", owasp_asi="",
                    evidence=f"{hdr}: {headers[hdr]}",
                    file=url, line=1, detail=f"{label} header exposed",
                ))

        # Body heuristics for an LLM endpoint
        body_lower = body.lower()
        if any(k in body_lower for k in ("chat", "completion", "llm", "gpt", "claude")):
            findings.append(SurfaceFinding(
                bug_class="prompt-injection", severity="high",
                owasp_llm="LLM01", owasp_asi="ASI01",
                evidence="body references chat/completion/LLM",
                file=url, line=1, detail="Likely LLM endpoint — hunt prompt injection",
            ))
        return findings

    def summarize(self, findings: List[SurfaceFinding]) -> Dict:
        by_class: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        for f in findings:
            by_class[f.bug_class] = by_class.get(f.bug_class, 0) + 1
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {"total": len(findings), "by_bug_class": by_class, "by_severity": by_sev}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf LLM / Agentic AI Attack-Surface Detector v1.0.0")
    parser.add_argument("--path", help="File or directory to scan (static)")
    parser.add_argument("--url", help="Live URL to fingerprint (light, passive)")
    parser.add_argument("--scope-file", help="Explicit authorization scope for --url")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Emit structured JSON")
    parser.add_argument("--min-severity", default="informational",
                        choices=["informational", "low", "medium", "high", "critical"],
                        help="Only report findings at/above this severity")
    args = parser.parse_args()

    if not args.path and not args.url:
        parser.error("one of --path or --url is required")

    scanner = LLMAttackSurfaceScanner(min_severity=args.min_severity)
    findings: List[SurfaceFinding] = []

    if args.path:
        findings = scanner.scan_path(args.path)
    if args.url:
        findings = scanner.scan_url(args.url, scope_file=args.scope_file)

    if args.as_json:
        print(json.dumps({
            "schema": "llm_attack_surface/1.0",
            "summary": scanner.summarize(findings),
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
        return

    print("=" * 72)
    print("  BUGWOLF LLM / AGENTIC ATTACK-SURFACE DETECTOR v1.0.0")
    print("=" * 72)
    s = scanner.summarize(findings)
    print(f"  Surfaces detected: {s['total']}")
    print(f"  By severity: {s['by_severity'] or '{}'}")
    print(f"  By bug class: {s['by_bug_class'] or '{}'}")
    print("=" * 72)

    if not findings:
        print("  No LLM/agentic attack surface detected.")
        return

    for f in findings:
        tag = " ".join(x for x in [f.owasp_llm, f.owasp_asi] if x) or "-"
        print(f"\n  [{f.severity.upper()}] {f.bug_class}  ({tag})")
        print(f"    {f.file}:{f.line}")
        print(f"    evidence: {f.evidence}")
        print(f"    detail: {f.detail}")


if __name__ == "__main__":
    main()
