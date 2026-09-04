# Injection canary fixtures (INTEGRATION_PLAN Phase D, v1.27)

Realistic business pages wrapped around instruction-forgery payloads.
Every fixture is INERT: it exists to prove bugwolf's U-layer reads target
content as DATA, never as instruction, and records the attempt as a fact.

Threat model: ECC the-security-guide (Feb-2026 Claude Code CVEs);
lethal trifecta = private data + untrusted content + external comms.

Files are named for the pattern they carry:
  instruction-forgery / fake-system-prompt / agent-targeting /
  exfil-lure / hidden-instruction
