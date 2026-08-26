#!/usr/bin/env python3
"""BugWolf Price-Manipulation Analyzer — lifecycle-oriented oracle/price audit.

Scans a DeFi contract (or invariant-model description) for price/oracle
dependencies and plans manipulation scenarios against each one (arXiv
2608.15518 lifecycle method):

  * **AMM spot price** — pricing from live reserves (spot) with no TWAP:
    a flash loan can skew reserves and move the price for one transaction.
  * **TWAP window** — time-weighted average with a short / settable window:
    multi-block manipulation within the window moves the average.
  * **External oracle** — Chainlink-style reads with no staleness/`latestAnswer`
    checks, or a settable oracle contract: direct price control.
  * **Flash-loan surface** — ``flashLoan``/``onFlashLoan`` callbacks that
    interact with pricing inside the same transaction as the price read.
  * **Mint/burn ratio** — minting/burning governed by a manipulable ratio
    (reserve ratio, share price): one-sided swaps change the ratio.

Each scenario includes preconditions, the manipulation sequence, and the
validation step (lab replay).  Output lands at
``research/<target>/contracts/price-manipulation-plans.json`` (a ``research``
artifact) and emits ``LLM_CANDIDATE`` for high-severity plans.

Offline and deterministic; uncensored; no chain is contacted.

Usage:
  python3 tools/domains/smart_contracts/price_manipulation_analyzer.py \
      --target acme --contract Vault.sol
  python3 tools/domains/smart_contracts/price_manipulation_analyzer.py \
      --target acme --contract Vault.sol --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _repo_root() -> Path:
    """Walk up from this module until the tools/ package root is found."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "tools" / "runtime_paths.py").is_file():
            return current
        current = current.parent
    return current


_CODE_ROOT = _repo_root()
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))
from tools.runtime_paths import workspace_root

try:
    from tools.core.signal_bus import SignalBus
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus

SCHEMA = "bugwolf/price-manipulation-analyzer/v1"

# Dependency markers: (pattern, dependency_id, label)
DEPENDENCY_MARKERS: List[Dict[str, Any]] = [
    {"pattern": r"getReserves|reserve0|reserve1|sqrt\s*\(|amm|pair|pool",
     "dep": "amm_spot_price", "label": "AMM live reserves (spot price)"},
    {"pattern": r"twap|observation|period\s*=|window|timeWeighted",
     "dep": "twap_window", "label": "time-weighted average price window"},
    {"pattern": r"chainlink|latestAnswer|latestRoundData|priceFeed|oracle\s*\(",
     "dep": "external_oracle", "label": "external oracle read"},
    {"pattern": r"flashLoan|onFlashLoan|flashMint|callback",
     "dep": "flash_loan_surface", "label": "flash-loan callback surface"},
    {"pattern": r"mint\s*\(|burn\s*\(|ratio|sharePrice|totalSupply.*reserve",
     "dep": "mint_burn_ratio", "label": "mint/burn governed by a ratio"},
]


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class PriceDependency:
    dependency_id: str
    label: str
    evidence: str
    severity: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ManipulationPlan:
    plan_id: str
    dependency: str
    title: str
    severity: str
    preconditions: List[str] = field(default_factory=list)
    sequence: List[str] = field(default_factory=list)
    validation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PriceManipulationAnalysis:
    target: str
    generated_at: str
    contract: str
    dependencies: List[PriceDependency] = field(default_factory=list)
    plans: List[ManipulationPlan] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "contract": self.contract,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "plans": [p.to_dict() for p in self.plans],
        }


def _detect_dependencies(code: str) -> List[PriceDependency]:
    deps: List[PriceDependency] = []
    for marker in DEPENDENCY_MARKERS:
        match = re.search(marker["pattern"], code, re.IGNORECASE)
        if not match:
            continue
        evidence = code[max(0, match.start() - 40):match.end() + 40]
        evidence = " ".join(evidence.split())
        severity = "high" if marker["dep"] in (
            "amm_spot_price", "external_oracle") else "medium"
        deps.append(PriceDependency(
            dependency_id=marker["dep"],
            label=marker["label"],
            evidence=evidence,
            severity=severity,
        ))
    return deps


def _plans_for(dep: PriceDependency, has_flash: bool) -> List[ManipulationPlan]:
    dep_id = dep.dependency_id
    plans: List[ManipulationPlan] = []
    if dep_id == "amm_spot_price":
        plans.append(ManipulationPlan(
            plan_id=_id("pm", dep_id, "flash-swap"),
            dependency=dep_id,
            title="Flash-loan reserve skew -> spot price move",
            severity="high",
            preconditions=[
                "Price is read from live reserves (no TWAP) in the same "
                "transaction as a swap the attacker can perform.",
                "The priced asset is a liquid pair with borrowable liquidity.",
            ],
            sequence=[
                "Flash-borrow the base asset.",
                "Swap to skew the pair's reserves (move spot price).",
                "Exercise the victim contract's price-sensitive function "
                "(borrow, liquidate, mint, settle) at the skewed price.",
                "Swap back and repay the flash loan in the same transaction.",
            ],
            validation="Replay in the verification lab on a forked chain: "
                       "assert the victim function executed at the skewed "
                       "price and the attacker netted profit after fees.",
        ))
    elif dep_id == "twap_window":
        plans.append(ManipulationPlan(
            plan_id=_id("pm", dep_id, "window-skew"),
            dependency=dep_id,
            title="TWAP window manipulation (short or settable window)",
            severity="high",
            preconditions=[
                "TWAP window is short (few blocks/minutes) or settable by a "
                "caller.",
                "The protocol does not require a minimum observation count.",
            ],
            sequence=[
                "Move the price in one direction over the window length "
                "(one large block, or repeated small swaps).",
                "Trigger the victim function while the average is skewed.",
                "Let the window roll back to the true price afterwards.",
            ],
            validation="Lab replay with a controlled block schedule: confirm "
                       "the average can be pushed past the liquidation/borrow "
                       "threshold.",
        ))
    elif dep_id == "external_oracle":
        plans.append(ManipulationPlan(
            plan_id=_id("pm", dep_id, "oracle-stale"),
            dependency=dep_id,
            title="Oracle staleness / settable-oracle manipulation",
            severity="high",
            preconditions=[
                "Oracle read lacks staleness checks (updatedAt/round age).",
                "Or the oracle address is settable (admin or constructor "
                "parameter without validation).",
            ],
            sequence=[
                "If settable: point the price feed at an attacker-owned "
                "oracle returning a chosen price.",
                "If stale-tolerant: wait for the feed to go stale, then "
                "exercise price-sensitive logic at the old price.",
                "Profit from the divergence (borrow/liquidate/mint).",
            ],
            validation="Lab replay: deploy a mock feed and confirm the "
                       "victim accepts the manipulated price.",
        ))
    elif dep_id == "flash_loan_surface" and has_flash:
        plans.append(ManipulationPlan(
            plan_id=_id("pm", dep_id, "callback-pricing"),
            dependency=dep_id,
            title="Flash-loan callback interacting with pricing",
            severity="medium",
            preconditions=[
                "A flashLoan/onFlashLoan callback can call into pricing or "
                "lending logic inside the loan.",
            ],
            sequence=[
                "Initiate a flash loan whose callback performs the "
                "price-sensitive action.",
                "Use the borrowed capital to move price and settle the "
                "victim operation within the callback.",
                "Repay principal + fee at the end of the callback.",
            ],
            validation="Lab replay: confirm the callback can reenter "
                       "price-sensitive functions during the loan.",
        ))
    elif dep_id == "mint_burn_ratio":
        plans.append(ManipulationPlan(
            plan_id=_id("pm", dep_id, "ratio-skew"),
            dependency=dep_id,
            title="Mint/burn ratio skew via one-sided swap",
            severity="medium",
            preconditions=[
                "Mint/burn quantities derive from a reserve ratio or share "
                "price computed from current reserves.",
            ],
            sequence=[
                "Perform a one-sided swap to shift the reserve ratio.",
                "Mint (or redeem) at the skewed ratio.",
                "Restore the ratio (or repeat across assets).",
            ],
            validation="Lab replay: assert mint/redeem values at skewed vs "
                       "restored ratios differ beyond fees.",
        ))
    return plans


def analyze(target: str, contract: str, code: str) -> PriceManipulationAnalysis:
    """Deterministically plan price-manipulation scenarios for a contract."""
    analysis = PriceManipulationAnalysis(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
        contract=contract,
    )
    deps = _detect_dependencies(code)
    analysis.dependencies = deps
    has_flash = any(d.dependency_id == "flash_loan_surface" for d in deps)
    for dep in deps:
        analysis.plans.extend(_plans_for(dep, has_flash))
    return analysis


def write_analysis(analysis: PriceManipulationAnalysis, *,
                   project_root: Optional[str] = None,
                   base_dir: Optional[str] = None) -> Path:
    """Persist to research/<target>/contracts/price-manipulation-plans.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_slug = re.sub(r"[^\w.-]+", "_", analysis.target) or "default"
    out_dir = root / "research" / target_slug / "contracts"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "price-manipulation-plans.json"
    out.write_text(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Price/oracle manipulation analyzer")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--contract", default="contract.sol",
                        help="contract name (for the report)")
    parser.add_argument("--code", default=None,
                        help="path to contract source (or use --code-text)")
    parser.add_argument("--code-text", default=None, help="inline contract source")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    code = args.code_text
    if args.code:
        try:
            code = Path(args.code).read_text(errors="replace")
        except OSError as exc:
            print(json.dumps({"error": f"cannot read contract: {exc}"}))
            return 2
    if not code:
        print(json.dumps({"error": "supply --code or --code-text"}))
        return 2

    analysis = analyze(args.target, args.contract, code)
    out = write_analysis(analysis, project_root=args.project_root,
                         base_dir=args.base_dir)

    high = [p for p in analysis.plans if p.severity == "high"]
    if high:
        try:
            bus = SignalBus(args.target,
                            project_root=args.project_root or args.base_dir)
            for plan in high:
                bus.publish("LLM_CANDIDATE", source="price_manipulation_analyzer",
                            payload={"dependency": plan.dependency,
                                     "title": plan.title,
                                     "severity": plan.severity})
        except Exception as exc:  # advisory, never a gate
            print(f"[!] signal publish skipped: {type(exc).__name__}: {exc}",
                  file=sys.stderr)

    if args.json:
        print(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"[+] {args.target}: {len(analysis.dependencies)} dependencies, "
              f"{len(analysis.plans)} manipulation plans -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
