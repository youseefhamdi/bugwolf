#!/usr/bin/env python3
"""Stateful two-account workflow support for private Web/API fixtures."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional

SCHEMA = "bugwolf/multitenant-workflow/v1"


@dataclass
class WorkflowStep:
    name: str
    method: str
    path: str
    body: Optional[Mapping[str, Any]] = None
    expected_status: Optional[int] = None
    login: bool = False


@dataclass
class AccountRun:
    account_id: str
    observations: List[Dict[str, Any]] = field(default_factory=list)


class MultiTenantWorkflow:
    """Replay identical workflows as multiple identities with session state."""

    def __init__(self, base_url: str, *, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, step: WorkflowStep, headers: Mapping[str, str]) -> Dict[str, Any]:
        url = self.base_url + step.path
        data = None
        request_headers = {str(k): str(v) for k, v in headers.items()}
        if step.body is not None:
            data = json.dumps(dict(step.body)).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(url, data=data, headers=request_headers,
                                         method=step.method.upper())
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
        try:
            payload: Any = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            payload = raw.decode("utf-8", errors="replace")
        return {"status": status, "body": payload,
                "expected_status": step.expected_status}

    def run(self, steps: Iterable[WorkflowStep], accounts: Mapping[str, Mapping[str, str]]) -> Dict[str, Any]:
        if len(accounts) < 2:
            raise ValueError("at least two accounts are required")
        step_list = list(steps)
        runs = []
        for account_id, account in accounts.items():
            headers = {str(k): str(v) for k, v in account.items()}
            run = AccountRun(str(account_id))
            for step in step_list:
                observation = self._request(step, headers)
                if step.login and isinstance(observation["body"], dict):
                    token = observation["body"].get("token")
                    if token:
                        headers["Authorization"] = f"Bearer {token}"
                        observation["session_established"] = True
                observation["step"] = step.name
                observation["account_id"] = str(account_id)
                run.observations.append(observation)
            runs.append(run)
        comparison = self.compare(runs)
        return {"schema": SCHEMA, "accounts": [run.__dict__ for run in runs],
                "comparison": comparison}

    @staticmethod
    def compare(runs: List[AccountRun]) -> Dict[str, Any]:
        if len(runs) < 2:
            return {"isolation_violation": False, "reason": "insufficient accounts"}
        baseline = runs[0]
        violations = []
        for index, observation in enumerate(baseline.observations):
            for other in runs[1:]:
                if index >= len(other.observations):
                    continue
                peer = other.observations[index]
                if observation["status"] != peer["status"]:
                    continue
                if observation["body"] != peer["body"]:
                    continue
                body = observation["body"]
                if isinstance(body, (dict, list)) and body:
                    violations.append({"step": observation["step"],
                                       "accounts": [baseline.account_id, other.account_id],
                                       "status": observation["status"],
                                       "shared_body": body})
        return {"isolation_violation": bool(violations), "violations": violations}
