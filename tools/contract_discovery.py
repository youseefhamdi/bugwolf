#!/usr/bin/env python3
"""Smart-contract state-space exploration for BugWolf's discovery core.

Extends the Web/API discovery core to contract invariant + sequence testing
using the *same* coverage loop: it builds a serializable contract surface
model, generates bounded sequence/boundary/role/reentrancy mutation plans, and
runs them through a deterministic in-memory executor that checks invariants
after every call.

This generalizes ``zero_day_tracks.SmartContractTrack.explore_sequences`` into
a coverage-aware, scheduler-driven search. It reuses
:class:`tools.discovery_scheduler.CoverageTracker` verbatim so Web and contract
searches share one coverage/ordering discipline.

Execution is an in-memory simulation over caller-supplied transition and
invariant predicates — no chain, fork, transaction, or model call happens here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

try:
    from tools.discovery_scheduler import CoverageTracker
    from tools.impact_focus import CriticalityRouter, infer_verb
except ImportError:  # direct script execution
    from discovery_scheduler import CoverageTracker
    from impact_focus import CriticalityRouter, infer_verb

SCHEMA_VERSION = "bugwolf-contract-discovery-v1"


# ---------------------------------------------------------------------------
# Contract surface model
# ---------------------------------------------------------------------------

@dataclass
class ContractArgument:
    name: str
    type: str                     # uint256 | int256 | address | bool | bytes32 | ...
    default: Any = None

    def boundary_values(self) -> List[Any]:
        t = self.type.lower()
        if t.startswith("uint"):
            return [0, 1, 2 ** 256 - 1, 2 ** 255]
        if t.startswith("int"):
            return [0, 1, -1, 2 ** 255 - 1, -(2 ** 255)]
        if t == "address":
            return ["0x0", "attacker", "victim", "owner"]
        if t == "bool":
            return [True, False]
        if t in ("bytes", "bytes32"):
            return ["", "0x" + "00" * 32]
        if t == "string":
            return ["", "a" * 64]
        return [0, "", "0x0"]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractArgument":
        return cls(**data)


@dataclass
class ContractFunction:
    name: str
    args: List[ContractArgument] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)   # empty => anyone
    payable: bool = False
    impact: str = ""                                  # override inferred verb
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["args"] = [a.to_dict() for a in self.args]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractFunction":
        raw = dict(data)
        raw["args"] = [ContractArgument.from_dict(a) for a in raw.get("args", [])]
        return cls(**raw)


@dataclass
class ContractInvariant:
    name: str
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractInvariant":
        return cls(**data)


@dataclass
class ContractSurfaceModel:
    target: str
    functions: List[ContractFunction] = field(default_factory=list)
    invariants: List[ContractInvariant] = field(default_factory=list)
    roles: List[str] = field(default_factory=lambda: ["attacker", "user", "owner"])
    metadata: Dict[str, Any] = field(default_factory=dict)

    def function(self, name: str) -> Optional[ContractFunction]:
        for fn in self.functions:
            if fn.name == name:
                return fn
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "target": self.target,
            "functions": [f.to_dict() for f in self.functions],
            "invariants": [i.to_dict() for i in self.invariants],
            "roles": list(self.roles),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractSurfaceModel":
        return cls(
            target=data["target"],
            functions=[ContractFunction.from_dict(f) for f in data.get("functions", [])],
            invariants=[ContractInvariant.from_dict(i) for i in data.get("invariants", [])],
            roles=list(data.get("roles", ["attacker", "user", "owner"])),
            metadata=dict(data.get("metadata", {})),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# Contract mutation plans
# ---------------------------------------------------------------------------

@dataclass
class ContractMutation:
    mutation_id: str
    function: str                 # last function in the sequence
    sequence: List[str]           # full call sequence (order matters)
    caller: str = "attacker"
    args: Dict[str, Any] = field(default_factory=dict)
    kind: str = "sequence"        # sequence | boundary | role | reentrancy
    variable: str = ""            # argument name for boundary mutations
    bug_class: str = "invariant_violation"
    risk: str = "active"
    notes: str = ""

    def key(self) -> str:
        """Coverage key shared with the Web discovery core's CoverageTracker."""
        if self.kind == "boundary":
            return f"{self.function}|{self.variable}|{self.kind}"
        if self.kind == "role":
            return f"{self.function}|{self.caller}|{self.kind}"
        if self.kind == "reentrancy":
            return f"{self.function}|{self.caller}|{self.kind}"
        return f"{'->'.join(self.sequence)}|{self.caller}|{self.kind}"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["schema"] = SCHEMA_VERSION
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractMutation":
        raw = dict(data)
        raw.pop("schema", None)
        return cls(**raw)


_CONTRACT_VERBS = {
    "withdraw": ["withdraw", "redeem", "cashout", "claim"],
    "transfer": ["transfer", "transferfrom", "send", "move", "pay", "donate"],
    "impersonate": ["impersonat", "setowner", "changeowner", "setadmin",
                    "grantrole", "revokerole", "setrole"],
    "authorize": ["approve", "authorize", "permit", "setapproval", "allow"],
    "create": ["mint", "create", "register", "issue", "deploy"],
    "modify": ["update", "set", "configure", "initialize", "reinit"],
    "delete": ["burn", "destroy", "remove", "revoke", "pause", "stop"],
    "read": ["balanceof", "get", "view", "total", "balance"],
}


def contract_impact_verb(name: str) -> str:
    n = (name or "").lower()
    for verb, keywords in _CONTRACT_VERBS.items():
        if any(k in n for k in keywords):
            return verb
    return infer_verb(n)


class ContractMutator:
    """Generate bounded sequence/argument/role/reentrancy mutation plans."""

    def __init__(self, *, max_depth: int = 3, max_sequences: int = 256,
                 max_per_arg: int = 4):
        self.max_depth = max(1, max_depth)
        self.max_sequences = max(1, max_sequences)
        self.max_per_arg = max(1, max_per_arg)

    def _add(self, out: List[ContractMutation], function: str, sequence: List[str],
             caller: str, args: Dict[str, Any], kind: str, variable: str = "",
             notes: str = "") -> bool:
        if len(out) >= self.max_sequences:
            return False
        raw = "|".join([function, "->".join(sequence), caller, kind, variable,
                        json.dumps(args, sort_keys=True, default=str)])
        out.append(ContractMutation(
            mutation_id=hashlib.sha256(raw.encode()).hexdigest()[:16],
            function=function, sequence=list(sequence), caller=caller,
            args=dict(args), kind=kind, variable=variable, notes=notes))
        return True

    def mutations(self, model: ContractSurfaceModel) -> List[ContractMutation]:
        out: List[ContractMutation] = []
        names = [f.name for f in model.functions]

        # 1. Boundary arguments (single call, one argument at a time).
        for fn in model.functions:
            for arg in fn.args:
                for value in arg.boundary_values()[:self.max_per_arg]:
                    self._add(out, fn.name, [fn.name], "attacker",
                              {arg.name: value}, "boundary", arg.name,
                              f"{arg.name}={value!r}")

        # 2. Role mutations (same call, different caller).
        for fn in model.functions:
            for role in model.roles:
                self._add(out, fn.name, [fn.name], role, {}, "role", "",
                          f"call {fn.name} as {role}")

        # 3. Reentrancy (same function twice).
        for fn in model.functions:
            self._add(out, fn.name, [fn.name, fn.name], "attacker", {},
                      "reentrancy", "", f"re-enter {fn.name}")

        # 4. Sequence exploration (bounded BFS over function names).
        frontier = [[n] for n in names]
        for sequence in frontier:
            self._add(out, sequence[-1], sequence, "attacker", {}, "sequence",
                      "", "->".join(sequence))
        while frontier and len(out) < self.max_sequences:
            prefix = frontier.pop(0)
            if len(prefix) >= self.max_depth:
                continue
            for n in names:
                seq = prefix + [n]
                if not self._add(out, seq[-1], seq, "attacker", {}, "sequence",
                                 "", "->".join(seq)):
                    break
                frontier.append(seq)
        return out


# ---------------------------------------------------------------------------
# Deterministic in-memory executor
# ---------------------------------------------------------------------------

@dataclass
class ContractObservation:
    mutation_id: str = ""
    sequence: List[str] = field(default_factory=list)
    caller: str = ""
    args: Dict[str, Any] = field(default_factory=dict)
    state: Dict[str, Any] = field(default_factory=dict)
    invariants: Dict[str, bool] = field(default_factory=dict)  # name -> holds
    violated: List[str] = field(default_factory=list)
    error: str = ""
    trace: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def state_hash(self) -> str:
        return hashlib.sha256(
            json.dumps(self.state, sort_keys=True, default=str).encode()).hexdigest()[:16]

    def violated_any(self) -> bool:
        return bool(self.violated)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["state_hash"] = self.state_hash
        data["schema"] = SCHEMA_VERSION
        return data


class ContractExecutor:
    """Apply caller-supplied transitions and invariant predicates.

    ``transitions`` maps function name -> ``fn(state, call) -> state`` where
    ``call`` is ``{"caller": str, "args": dict}``. ``invariants`` maps name ->
    ``predicate(state) -> bool``. The executor is pure: it deep-copies the
    initial state and never mutates the caller's objects.
    """

    def __init__(self, initial_state: Dict[str, Any],
                 transitions: Dict[str, Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]],
                 invariants: Dict[str, Callable[[Dict[str, Any]], bool]],
                 *, default_args: Optional[Dict[str, Dict[str, Any]]] = None):
        self.initial_state = initial_state
        self.transitions = transitions
        self.invariants = invariants
        self.default_args = default_args or {}

    def _apply(self, state: Dict[str, Any], name: str,
               caller: str, args: Dict[str, Any]) -> Dict[str, Any]:
        fn = self.transitions.get(name)
        if fn is None:
            raise KeyError(f"no transition for {name!r}")
        call_args = dict(self.default_args.get(name, {}))
        call_args.update(args or {})
        return fn(state, {"caller": caller, "args": call_args})

    def execute(self, mutation: ContractMutation) -> ContractObservation:
        obs = ContractObservation(
            mutation_id=mutation.mutation_id, sequence=list(mutation.sequence),
            caller=mutation.caller, args=dict(mutation.args))
        state = {k: v for k, v in self.initial_state.items()}
        try:
            for name in mutation.sequence:
                state = self._apply(state, name, mutation.caller, mutation.args)
                obs.trace.append({"function": name,
                                  "state": {k: v for k, v in state.items()}})
        except Exception as exc:
            obs.error = str(exc)[:400]
            obs.state = state
            return obs
        obs.state = state
        for inv_name, predicate in self.invariants.items():
            holds = bool(predicate(state))
            obs.invariants[inv_name] = holds
            if not holds:
                obs.violated.append(inv_name)
        return obs

    def _violates(self, sequence: List[str], caller: str,
                  args: Dict[str, Any]) -> bool:
        state = {k: v for k, v in self.initial_state.items()}
        for name in sequence:
            try:
                state = self._apply(state, name, caller, args)
            except Exception:
                return False
        return any(not bool(pred(state)) for pred in self.invariants.values())

    def minimize(self, sequence: List[str], caller: str,
                 args: Dict[str, Any]) -> List[str]:
        """Greedily shrink a violating sequence to a minimal reproducer.

        Deterministic subsequence minimization: repeatedly drops the first
        call whose removal still leaves the invariant broken, until no single
        removal preserves the violation.
        """
        minimal = list(sequence)
        changed = True
        while changed and len(minimal) > 1:
            changed = False
            for index in range(len(minimal)):
                candidate = minimal[:index] + minimal[index + 1:]
                if self._violates(candidate, caller, args):
                    minimal = candidate
                    changed = True
                    break
        return minimal


# ---------------------------------------------------------------------------
# Scheduler (reuses the Web discovery core's coverage loop)
# ---------------------------------------------------------------------------

@dataclass
class ContractRunSummary:
    target: str = ""
    mutations_run: int = 0
    violations: int = 0
    clean: int = 0
    errors: int = 0
    by_invariant: Dict[str, int] = field(default_factory=dict)
    minimal_reproducers: List[Dict[str, Any]] = field(default_factory=list)
    started_at: str = ""

    def __post_init__(self) -> None:
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["schema"] = SCHEMA_VERSION
        return data


class ContractDiscoveryScheduler:
    """Rank/allocate/run contract mutations through the shared coverage loop."""

    def __init__(self, model: ContractSurfaceModel,
                 executor: Optional[ContractExecutor] = None,
                 router: Optional[CriticalityRouter] = None):
        self.model = model
        self.executor = executor
        self.router = router or CriticalityRouter()

    def _focus(self) -> Dict[str, Any]:
        surfaces = [{
            "id": fn.name,
            "endpoint": fn.name,
            "method": "POST",
            "title": fn.notes or fn.name,
            "impact_verb": fn.impact or contract_impact_verb(fn.name),
        } for fn in self.model.functions]
        scored = self.router.route(surfaces)
        return {s.surface_id: s for s in scored}

    def rank(self, coverage: Optional[CoverageTracker] = None) -> List[ContractMutation]:
        coverage = coverage or CoverageTracker()
        focus = self._focus()
        focus_rank = CriticalityRouter.FOCUS_RANK
        mutations = ContractMutator().mutations(self.model)
        kind_rank = {"reentrancy": 0, "sequence": 1, "role": 2, "boundary": 3}

        def sort_key(m: ContractMutation) -> tuple:
            fs = focus.get(m.function)
            tier = focus_rank.get(fs.focus, 3) if fs else 3
            untried = 0 if not coverage.is_tried(m.key()) else 1
            return (tier, untried, kind_rank.get(m.kind, 99),
                    len(m.sequence), m.function)
        return sorted(mutations, key=sort_key)

    def allocate(self, coverage: CoverageTracker,
                 budget: int) -> List[ContractMutation]:
        budget = max(0, budget)
        ranked = self.rank(coverage)
        untried = [m for m in ranked if not coverage.is_tried(m.key())]
        if len(untried) >= budget:
            return untried[:budget]
        picked = list(untried)
        for m in ranked:
            if len(picked) >= budget:
                break
            if coverage.is_tried(m.key()) and m not in picked:
                picked.append(m)
        return picked[:budget]

    def run(self, mutations: List[ContractMutation], coverage: CoverageTracker,
            executor: Optional[ContractExecutor] = None) -> ContractRunSummary:
        """Execute mutations and record invariant violations into coverage."""
        executor = executor or self.executor
        if executor is None:
            raise ValueError("a ContractExecutor is required to run mutations")
        summary = ContractRunSummary(target=self.model.target)
        for mutation in mutations:
            coverage.mark_tried(mutation.key())
            obs = executor.execute(mutation)
            summary.mutations_run += 1
            if obs.error:
                summary.errors += 1
                continue
            if obs.violated:
                summary.violations += 1
                for name in obs.violated:
                    summary.by_invariant[name] = summary.by_invariant.get(name, 0) + 1
                minimal = executor.minimize(obs.sequence, mutation.caller,
                                            mutation.args)
                summary.minimal_reproducers.append({
                    "mutation_id": mutation.mutation_id,
                    "sequence": minimal,
                    "caller": mutation.caller,
                    "args": mutation.args,
                    "invariants": list(obs.violated),
                    "state_hash": obs.state_hash,
                })
            else:
                summary.clean += 1
        return summary


# ---------------------------------------------------------------------------
# CLI (plan mode only — execution is programmatic via ContractExecutor)
# ---------------------------------------------------------------------------

def load_contract_spec(path: str) -> ContractSurfaceModel:
    data = json.loads(Path(path).read_text())
    if data.get("functions") is None and "abi" in data:
        data = _from_abi(data)
    return ContractSurfaceModel.from_dict(data)


def _from_abi(data: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce a minimal ABI JSON shape into the contract spec shape."""
    functions = []
    for entry in data.get("abi", []):
        if entry.get("type") != "function":
            continue
        args = [{"name": (item.get("name") or f"arg{idx}"),
                 "type": (item.get("type") or "uint256")}
                for idx, item in enumerate(entry.get("inputs", []))]
        functions.append({
            "name": entry.get("name", ""),
            "args": args,
            "payable": entry.get("stateMutability") == "payable",
        })
    return {"target": data.get("target", data.get("name", "Contract")),
            "functions": functions, "invariants": [], "roles": ["attacker", "user", "owner"]}


def main() -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="BugWolf smart-contract discovery core")
    parser.add_argument("--target", help="Contract name (overrides spec)")
    parser.add_argument("--spec", required=True,
                        help="Contract spec JSON (functions, invariants, roles)")
    parser.add_argument("--output-dir", default="contract-discovery")
    parser.add_argument("--budget", type=int, default=200)
    parser.add_argument("--min-focus", default="medium",
                        choices=["critical", "high", "medium", "low"])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        model = load_contract_spec(args.spec)
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(2)
    if args.target:
        model.target = args.target

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    coverage = CoverageTracker()
    cov_file = out_dir / "coverage.json"
    if cov_file.exists():
        try:
            coverage = CoverageTracker.from_dict(json.loads(cov_file.read_text()))
        except (json.JSONDecodeError, TypeError):
            pass

    scheduler = ContractDiscoveryScheduler(
        model, router=CriticalityRouter(min_focus=args.min_focus))
    ranked = scheduler.rank(coverage)
    allocation = scheduler.allocate(coverage, args.budget)

    (out_dir / "contract-model.json").write_text(model.to_json() + "\n")
    (out_dir / "coverage.json").write_text(json.dumps(coverage.to_dict(), indent=2) + "\n")
    with open(out_dir / "plan.jsonl", "w") as stream:
        for m in allocation:
            stream.write(json.dumps(m.to_dict(), default=str) + "\n")

    if args.json:
        print(json.dumps({
            "schema": SCHEMA_VERSION,
            "target": model.target,
            "functions": len(model.functions),
            "invariants": len(model.invariants),
            "roles": model.roles,
            "mutations_ranked": len(ranked),
            "mutations_allocated": len(allocation),
            "coverage": coverage.to_dict(),
            "plan": [m.to_dict() for m in allocation],
        }, indent=2, default=str))
    else:
        print(f"[*] Contract discovery plan for {model.target}")
        print(f"    functions: {len(model.functions)}  invariants: "
              f"{len(model.invariants)}  roles: {model.roles}")
        print(f"    mutations ranked: {len(ranked)}  allocated: {len(allocation)}")
        for m in allocation[:20]:
            print(f"    [{m.kind}] {'->'.join(m.sequence)} as {m.caller} "
                  f"{m.variable or ''}")
        print(f"    plan written to {out_dir / 'plan.jsonl'}")


if __name__ == "__main__":
    main()
