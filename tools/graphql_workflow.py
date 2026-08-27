#!/usr/bin/env python3
"""Offline GraphQL differential workflow helpers for private lab fixtures."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional

SCHEMA = "bugwolf/graphql-workflow/v1"


@dataclass
class GraphQLCase:
    name: str
    query: str
    variables: Optional[Mapping[str, Any]] = None
    headers: Optional[Mapping[str, str]] = None


def _request(base_url: str, case: GraphQLCase, timeout: float) -> Dict[str, Any]:
    payload = {"query": case.query}
    if case.variables is not None:
        payload["variables"] = dict(case.variables)
    request = urllib.request.Request(
        base_url.rstrip("/") + "/graphql",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **dict(case.headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw, status = response.read(), response.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
    try:
        body = json.loads(raw.decode())
    except (ValueError, UnicodeDecodeError):
        body = raw.decode("utf-8", errors="replace")
    return {"case": case.name, "status": status, "body": body}


def compare(cases: Iterable[GraphQLCase], observations: List[Dict[str, Any]]) -> Dict[str, Any]:
    observations = list(observations)
    violations = []
    for observation in observations:
        body = observation.get("body")
        if isinstance(body, dict) and "errors" not in body and body.get("data"):
            query = next((case.query for case in cases if case.name == observation.get("case")), "")
            lowered = query.lower()
            if "node(" in lowered or "users" in lowered or "alias" in lowered:
                violations.append({"case": observation.get("case"), "status": observation.get("status"),
                                   "reason": "object data returned by differential GraphQL case"})
    return {"schema": SCHEMA, "observations": observations,
            "potential_authorization_variants": violations,
            "introspection_enabled": any("__schema" in str(c.query) for c in cases)}


class GraphQLWorkflow:
    def __init__(self, base_url: str, *, timeout: float = 5.0):
        self.base_url = base_url
        self.timeout = timeout

    def run(self, cases: Iterable[GraphQLCase]) -> Dict[str, Any]:
        case_list = list(cases)
        observations = [_request(self.base_url, case, self.timeout) for case in case_list]
        return compare(case_list, observations)
