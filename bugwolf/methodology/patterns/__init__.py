"""Pattern catalog for the bugwolf methodology library.

Each subpackage (ssrf/, xss/, sqli/, idor/, auth/, deserialization/,
business_logic/, ci_cd/, cloud/, llm_ai/, mobile/, recon/, api/,
waf_bypass/) contains YAML files conforming to the
``bugwolf-methodology-pattern-v1`` schema.
"""

from bugwolf.methodology.search import PatternRecord, MethodologySearch

__all__ = ["PatternRecord", "MethodologySearch"]