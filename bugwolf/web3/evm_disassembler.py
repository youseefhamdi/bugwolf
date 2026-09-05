"""Minimal EVM bytecode disassembler.

Implements :class:`EVMDisassembler.disassemble` which decodes an EVM
byte stream into a stream of :class:`Instruction` records. The
disassembler covers PUSH1-PUSH32, DUP1-DUP16, SWAP1-SWAP16, LOG0-LOG4,
CALL-family, SSTORE/SLOAD, MSTORE/MLOAD, RETURN/REVERT/STOP,
SELFDESTRUCT, and the full arithmetic/comparison opcode set.

It is deliberately small and dependency-free; it is intended as a
local-first static-analysis primitive that downstream tools (e.g.
bytecode taint) can layer on top of without requiring a real
disassembler binary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


SCHEMA = "bugwolf-web3-evm-disassembler/v1"


# EVM opcodes (subset). Values are the byte mnemonic; "size" is the
# immediate-data width in bytes that follows the opcode (PUSHn has n).
# For DUP/SWAP/LOG the "size" column is unused.
OPCODE_TABLE: Dict[int, Tuple[str, int]] = {
    0x00: ("STOP", 0),
    0x01: ("ADD", 0),
    0x02: ("MUL", 0),
    0x03: ("SUB", 0),
    0x04: ("DIV", 0),
    0x05: ("SDIV", 0),
    0x06: ("MOD", 0),
    0x07: ("SMOD", 0),
    0x08: ("ADDMOD", 0),
    0x09: ("MULMOD", 0),
    0x0A: ("EXP", 0),
    0x0B: ("SIGNEXTEND", 0),
    0x10: ("LT", 0),
    0x11: ("GT", 0),
    0x12: ("SLT", 0),
    0x13: ("SGT", 0),
    0x14: ("EQ", 0),
    0x15: ("ISZERO", 0),
    0x16: ("AND", 0),
    0x17: ("OR", 0),
    0x18: ("XOR", 0),
    0x19: ("NOT", 0),
    0x1A: ("BYTE", 0),
    0x1B: ("SHL", 0),
    0x1C: ("SHR", 0),
    0x1D: ("SAR", 0),
    0x20: ("SHA3", 0),
    0x30: ("ADDRESS", 0),
    0x31: ("BALANCE", 0),
    0x32: ("ORIGIN", 0),
    0x33: ("CALLER", 0),
    0x34: ("CALLVALUE", 0),
    0x35: ("CALLDATALOAD", 0),
    0x36: ("CALLDATASIZE", 0),
    0x37: ("CALLDATACOPY", 0),
    0x38: ("CODESIZE", 0),
    0x39: ("CODECOPY", 0),
    0x3A: ("GASPRICE", 0),
    0x3B: ("EXTCODESIZE", 0),
    0x3C: ("EXTCODECOPY", 0),
    0x3D: ("RETURNDATASIZE", 0),
    0x3E: ("RETURNDATACOPY", 0),
    0x3F: ("EXTCODEHASH", 0),
    0x40: ("BLOCKHASH", 0),
    0x41: ("COINBASE", 0),
    0x42: ("TIMESTAMP", 0),
    0x43: ("NUMBER", 0),
    0x44: ("DIFFICULTY", 0),
    0x45: ("GASLIMIT", 0),
    0x46: ("CHAINID", 0),
    0x47: ("SELFBALANCE", 0),
    0x48: ("BASEFEE", 0),
    0x49: ("BLOBHASH", 0),
    0x4A: ("BLOBBASEFEE", 0),
    0x50: ("POP", 0),
    0x51: ("MLOAD", 0),
    0x52: ("MSTORE", 0),
    0x53: ("MSTORE8", 0),
    0x54: ("SLOAD", 0),
    0x55: ("SSTORE", 0),
    0x56: ("JUMP", 0),
    0x57: ("JUMPI", 0),
    0x58: ("PC", 0),
    0x59: ("MSIZE", 0),
    0x5A: ("GAS", 0),
    0x5B: ("JUMPDEST", 0),
    0x5C: ("TLOAD", 0),
    0x5D: ("TSTORE", 0),
    0x5E: ("MCOPY", 0),
    0x5F: ("PUSH0", 0),
    0xF0: ("CREATE", 0),
    0xF1: ("CALL", 0),
    0xF2: ("CALLCODE", 0),
    0xF3: ("RETURN", 0),
    0xF4: ("DELEGATECALL", 0),
    0xF5: ("CREATE2", 0),
    0xFA: ("STATICCALL", 0),
    0xFD: ("REVERT", 0),
    0xFE: ("INVALID", 0),
    0xFF: ("SELFDESTRUCT", 0),
}
# PUSH1..PUSH32
for _i in range(1, 33):
    OPCODE_TABLE[0x60 + _i - 1] = (f"PUSH{_i}", _i)
# DUP1..DUP16
for _i in range(1, 17):
    OPCODE_TABLE[0x80 + _i - 1] = (f"DUP{_i}", 0)
# SWAP1..SWAP16
for _i in range(1, 17):
    OPCODE_TABLE[0x90 + _i - 1] = (f"SWAP{_i}", 0)
# LOG0..LOG4
for _i in range(0, 5):
    OPCODE_TABLE[0xA0 + _i] = (f"LOG{_i}", 0)


@dataclass(frozen=True)
class Instruction:
    """A single decoded EVM instruction."""

    pc: int
    opcode: int
    mnemonic: str
    immediate: bytes = b""

    def render(self) -> str:
        if self.immediate:
            return f"{self.pc:04x}: {self.mnemonic} 0x{self.immediate.hex()}"
        return f"{self.pc:04x}: {self.mnemonic}"

    def push_value(self) -> Optional[int]:
        """If this is a PUSHn, return the decoded integer value."""
        if not self.mnemonic.startswith("PUSH") or self.mnemonic == "PUSH0":
            return None
        return int.from_bytes(self.immediate, "big")


class EVMDisassembler:
    """Decodes EVM bytecode into a list of :class:`Instruction`."""

    SCHEMA_TAG = SCHEMA

    def disassemble(self, bytecode: bytes) -> List[Instruction]:
        """Decode ``bytecode`` into an instruction stream.

        Stops cleanly at STOP/RETURN/REVERT/SELFDESTRUCT/INVALID. On
        malformed input returns what was decoded so far.
        """
        instructions: List[Instruction] = []
        pc = 0
        data = bytecode
        while pc < len(data):
            op = data[pc]
            entry = OPCODE_TABLE.get(op)
            if entry is None:
                # Unknown opcode — emit a STOP-like marker and bail.
                instructions.append(Instruction(pc=pc, opcode=op, mnemonic="UNKNOWN"))
                break
            mnemonic, immediate_size = entry
            immediate = data[pc + 1 : pc + 1 + immediate_size]
            if len(immediate) < immediate_size:
                # Truncated immediate — bail.
                instructions.append(
                    Instruction(pc=pc, opcode=op, mnemonic=mnemonic, immediate=immediate)
                )
                break
            instructions.append(
                Instruction(pc=pc, opcode=op, mnemonic=mnemonic, immediate=immediate)
            )
            pc += 1 + immediate_size
            if mnemonic in ("STOP", "RETURN", "REVERT", "SELFDESTRUCT", "INVALID"):
                break
        return instructions


__all__ = [
    "EVMDisassembler",
    "Instruction",
    "OPCODE_TABLE",
    "SCHEMA",
]