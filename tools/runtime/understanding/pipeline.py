#!/usr/bin/env python3
"""The Understanding Layer pipeline: strict U1→U9, fail-closed (§8.2).

The thesis is enforced by construction: **you cannot hunt what you haven't
modeled.**  The pipeline refuses to run stage N+1 without stage N's stored
artifact, recomputes only stages whose inputs changed (hash-chained), and
ends in the coverage gate + Hunting Brief.

Inputs are real captured facts, never guesses:

    * ``pages``           — fetched text (U1): the caller (command, runner,
                            or MCP tool) fetches through the replay engine
                            under the scope gate;
    * ``crawl``           — ``authed_crawl.CrawlReport`` (U2/U3/U4/U6);
    * ``session_store``   — ``session_context.SessionContextStore`` (U4/U5);
    * ``openapi``         — the target's own schema document, if published;
    * ``probe_results``   — optional header/parser probe outputs (U6).

Deterministic tier: no model calls.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from tools.runtime.understanding.base import (
    STAGES, Assumption, ModelStore, UArtifact, canonical_hash,
)
from tools.runtime.understanding.stages import (
    COVERAGE_CLASSES, render_brief, stage_u1, stage_u2, stage_u3, stage_u4,
    stage_u5, stage_u6, stage_u7, stage_u8, stage_u9,
)

SCHEMA = "bugwolf-understanding-pipeline/v1"


class StagePrerequisiteError(RuntimeError):
    """Raised when a stage runs without its predecessor's artifact."""


@dataclass
class PipelineResult:
    """What one pipeline run produced (facts, never verdicts)."""

    target: str
    stages_run: List[str] = field(default_factory=list)
    stages_cached: List[str] = field(default_factory=list)
    artifacts: Dict[str, str] = field(default_factory=dict)
    coverage_hunts: List[str] = field(default_factory=list)
    coverage_parked: List[Dict[str, str]] = field(default_factory=list)
    ledger_size: int = 0
    model_hash: str = ""
    brief_path: str = ""
    predicted_chains: int = 0
    predicted_chains_path: str = ""
    injection_attempts: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA, "target": self.target,
            "stages_run": list(self.stages_run),
            "stages_cached": list(self.stages_cached),
            "artifacts": dict(self.artifacts),
            "coverage": {"hunts": list(self.coverage_hunts),
                         "parked": [dict(p) for p in self.coverage_parked]},
            "ledger_size": self.ledger_size,
            "model_hash": self.model_hash,
            "brief_path": self.brief_path,
            "predicted_chains": self.predicted_chains,
            "predicted_chains_path": self.predicted_chains_path,
        }


class UnderstandingPipeline:
    """Run U1→U9 in strict order against one target's captured facts."""

    def __init__(self, target: str, *, project_root=None,
                 store: Optional[ModelStore] = None) -> None:
        self.target = target
        self.store = store or ModelStore(target, project_root=project_root)

    # -- chaining ---------------------------------------------------------------

    def _inputs(self, stage: str, source_facts: Dict[str, Any],
                previous: Dict[str, str]) -> Dict[str, str]:
        """What this stage actually consumed (its hash-chain entry)."""
        inputs: Dict[str, str] = {}
        for name, value in sorted(source_facts.items()):
            inputs[name] = canonical_hash(value)
        for dep in self._dependencies(stage):
            if dep in previous:
                inputs[f"stage:{dep}"] = previous[dep]
        return inputs

    @staticmethod
    def _dependencies(stage: str) -> List[str]:
        # Strict sequence: every stage depends on ALL its predecessors
        # (fail-closed by construction, incremental by hash comparison).
        index = STAGES.index(stage)
        return list(STAGES[:index])

    def _previous_hashes(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for stage in STAGES[:-1]:
            artifact = self.store.load(stage)
            if artifact is None:
                return out  # caller fails closed before use
            out[stage] = artifact.artifact_hash
        return out

    def _assert_sequence(self, stage: str, previous: Dict[str, str]) -> None:
        for dep in self._dependencies(stage):
            if dep not in previous:
                raise StagePrerequisiteError(
                    f"{stage} requires {dep}'s artifact — run the pipeline "
                    "in order (fail-closed: you cannot hunt what you "
                    "haven't modeled)")

    # -- the run -----------------------------------------------------------------

    def run(self, *, pages: Optional[Dict[str, str]] = None,
            crawl: Any = None, session_store: Any = None,
            openapi: Optional[Dict[str, Any]] = None,
            probe_results: Optional[List[Dict[str, Any]]] = None,
            refresh: bool = False) -> PipelineResult:
        pages = dict(pages or {})
        stored_any = any(self.store.load(s) for s in STAGES)
        if not pages and crawl is None and session_store is None \
                and openapi is None and not probe_results and not stored_any:
            # Fail-closed (§8.2): no captured facts and no stored model —
            # a hollow pipeline must never emit a brief that dispatches
            # hunts.  You cannot hunt what you haven't modeled.
            raise StagePrerequisiteError(
                "no captured facts supplied (pages/crawl/session_store/"
                "openapi) and no stored model — run the deterministic "
                "captures first")
        result = PipelineResult(target=self.target)
        self.result = result   # post-run access (tests, bridge tools)
        stage_data: Dict[str, Dict[str, Any]] = {}
        previous = self._previous_hashes()
        ranked_assumptions: List[Assumption] = []

        fresh_facts = {
            "pages": pages,
            "crawl": (crawl.to_dict() if crawl is not None and
                      hasattr(crawl, "to_dict") else {}),
            "session_store": (session_store.to_model_dict()
                              if session_store is not None and
                              hasattr(session_store, "to_model_dict") else {}),
            "openapi": openapi or {},
            "probe_results": probe_results or [],
        }

        for stage in STAGES:
            self._assert_sequence(stage, previous)
            inputs = self._inputs(stage, fresh_facts, previous)

            if not refresh and not self.store.needs_recompute(stage, inputs):
                cached = self.store.load(stage)
                if cached is not None:
                    result.stages_cached.append(stage)
                    if stage != "U9":
                        stage_data[stage] = cached.data
                    if stage == "U8":
                        # U9's hypothesis pool survives a cached U8.
                        ranked_assumptions = [
                            Assumption(**d) for d in
                            cached.data.get("ranked", [])]
                    previous[stage] = cached.artifact_hash
                    continue

            assumptions: List[Assumption] = []
            data: Dict[str, Any] = {}
            md = ""

            if stage == "U1":
                data = stage_u1(pages, assumptions)
                # v1.27 Phase D: injection canaries.  Pages are untrusted
                # target content; an instruction-forgery attempt in them
                # is recorded as a FACT (and becomes hunting evidence),
                # never obeyed.  Facts land in the U1 artifact data.
                try:
                    from tools.understanding.canaries import scan_pages
                    attempts = scan_pages(pages)
                    if attempts:
                        data["injection_attempts"] = attempts
                        result.injection_attempts = list(attempts)
                except Exception:  # noqa: BLE001 - canary loss is not model loss
                    pass
            elif stage == "U2":
                data = stage_u2(crawl, openapi, stage_data.get("U1"), assumptions)
            elif stage == "U3":
                data = stage_u3(crawl, openapi, assumptions)
            elif stage == "U4":
                data = stage_u4(session_store, crawl, assumptions)
            elif stage == "U5":
                data = stage_u5(session_store, crawl, openapi, assumptions)
            elif stage == "U6":
                data = stage_u6(crawl, probe_results, assumptions)
            elif stage == "U7":
                data = stage_u7(stage_data.get("U1", {}),
                                stage_data.get("U4", {}),
                                stage_data.get("U5", {}),
                                openapi, assumptions)
            elif stage == "U8":
                ledger = [a for artifact in
                          (self.store.load(s) for s in STAGES[:7])
                          if artifact for a in artifact.assumptions]
                data, ranked_assumptions = stage_u8(ledger)
                # v1.27 Phase D: attempts detected in intake content lower
                # open-assumption confidence by the BOUNDED penalty — a
                # target that injection-baits its pages gets less trust.
                try:
                    attempts = len(getattr(result,
                                           "injection_attempts", []) or [])
                    if attempts:
                        from tools.understanding.canaries import \
                            apply_confidence_penalty
                        apply_confidence_penalty(
                            [a for a in ranked_assumptions
                             if hasattr(a, "confidence")], attempts)
                except Exception:  # noqa: BLE001 - penalty loss is not model loss
                    pass
            elif stage == "U9":
                data = stage_u9(stage_data, ranked_assumptions,
                                [c for c in self.store.chain()
                                 if c["stage"] != "U9"])

            # U8's seed list IS the artifact body: the ranked ledger rides
            # in assumptions (JSONL lines), not in `data`.
            artifact = UArtifact(
                stage=stage, target=self.target, data=data,
                assumptions=ranked_assumptions if stage == "U8" else assumptions,
                inputs=inputs)
            self.store.save(artifact)
            result.stages_run.append(stage)
            result.artifacts[stage] = str(self.store.stage_path(stage))
            if stage != "U9":
                stage_data[stage] = data
            previous[stage] = artifact.artifact_hash

        result.ledger_size = stage_data.get("U8", {}).get("ledger_size", 0)
        model = self.store.load("U9")
        if model is not None:
            result.model_hash = model.artifact_hash
            result.coverage_hunts = list(model.data.get("hunts", []))
            result.coverage_parked = list(model.data.get("parked", []))
        brief = render_brief(self.target, model.data if model else {},
                             stage_data)
        # §8.3 completion (v1.19): U7×U8 predicted chains are a U9 byproduct
        # — computed while the ledger is fresh, persisted as
        # ``predicted-chains.json``, and appended to the Hunting Brief so
        # the operator sees the first probes before any dispatch.  A
        # prediction failure NEVER fails the pipeline (the brief still
        # renders; the team engine recomputes on demand).
        try:
            from tools.runtime.understanding.chain_predict import ChainPredictor
            predictions, brief_lines = ChainPredictor(self.store).predict()
            if brief_lines:
                brief = brief.rstrip() + "\n" + "\n".join(brief_lines) + "\n"
            path = ChainPredictor(self.store).save(predictions)
            result.predicted_chains = len(predictions)
            result.predicted_chains_path = str(path)
        except Exception:  # noqa: BLE001 - prediction never gates the model
            pass
        brief_path = self.store.brief_path()
        brief_path.write_text(brief, encoding="utf-8")
        result.brief_path = str(brief_path)
        return result


def run_pipeline(target: str, **kwargs) -> PipelineResult:
    """Convenience entry (what the MCP bridge and runner call)."""
    return UnderstandingPipeline(target, project_root=kwargs.pop(
        "project_root", None)).run(**kwargs)
