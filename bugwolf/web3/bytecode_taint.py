"""EVM bytecode taint analysis.

Stub-safe taint tracer that walks the disassembled instruction stream
and follows data-flow from a "source" (any of CALLDATALOAD, CALLER,
ORIGIN, SLOAD) to a "sink" (any of SSTORE, CALL, DELEGATECALL,
STATICCALL, CALLCODE, CREATE, CREATE2, SELFDESTRUCT, RETURN, REVERT).

If neither a source nor a sink is supplied, ``trace()`` returns an
empty list — never raises.  The tracer is intentionally conservative:
it follows a single execution path linearly and ignores jumps; this
keeps it deterministic and cheap to run inside an audit pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set

from bugwolf.web3.evm_disassembler import EVMDisassembler, Instruction


SCHEMA = "bugwolf-web3-bytecode-taint/v1"


SINK_MNEMONICS: Set[str] = {
    "SSTORE",
    "CALL",
    "CALLCODE",
    "DELEGATECALL",
    "STATICCALL",
    "CREATE",
    "CREATE2",
    "SELFDESTRUCT",
    "RETURN",
    "REVERT",
}

SOURCE_MNEMONICS: Set[str] = {
    "CALLDATALOAD",
    "CALLER",
    "ORIGIN",
    "SLOAD",
    "BALANCE",
    "EXTCODESIZE",
    "EXTCODEHASH",
    "BLOCKHASH",
    "TIMESTAMP",
    "NUMBER",
    "GASPRICE",
}


@dataclass(frozen=True)
class TaintStep:
    pc: int
    mnemonic: str
    role: str  # "source" or "sink"

    def render(self) -> str:
        return f"pc=0x{self.pc:04x} {self.mnemonic} ({self.role})"


@dataclass(frozen=True)
class BytecodeTaintFlow:
    """Linear taint tracer over a disassembled stream."""

    bytecode: bytes = b""

    def trace(
        self,
        source: Optional[Iterable[str]] = None,
        sink: Optional[Iterable[str]] = None,
        *,
        max_steps: int = 4096,
    ) -> List[TaintStep]:
        """Walk the bytecode and emit TaintStep entries.

        Returns ``[]`` if no source or sink list is provided, or if
        the bytecode is empty.  Never raises.
        """
        if not self.bytecode:
            return []
        if source is None and sink is None:
            return []

        allowed_sources: Set[str] = set(source) if source else set(SOURCE_MNEMONICS)
        allowed_sinks: Set[str] = set(sink) if sink else set(SINK_MNEMONICS)
        if not allowed_sources or not allowed_sinks:
            return []

        disassembler = EVMDisassembler()
        instructions = disassembler.disassemble(self.bytecode)
        if not instructions:
            return []

        steps: List[TaintStep] = []
        seen_pcs: Set[int] = set()
        for ins in instructions[:max_steps]:
            if ins.pc in seen_pcs:
                continue
            seen_pcs.add(ins.pc)
            if ins.mnemonic in allowed_sources:
                steps.append(TaintStep(pc=ins.pc, mnemonic=ins.mnemonic, role="source"))
            elif ins.mnemonic in allowed_sinks:
                steps.append(TaintStep(pc=ins.pc, mnemonic=ins.mnemonic, role="sink"))
        return steps


__all__ = [
    "BytecodeTaintFlow",
    "TaintStep",
    "SOURCE_MNEMONICS",
    "SINK_MNEMONICS",
    "SCHEMA",
]