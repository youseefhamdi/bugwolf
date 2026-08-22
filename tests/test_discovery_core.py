"""Tests for the Web/API discovery core: surface model, mutator, scheduler."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.surface_model import (
    SurfaceModel, Operation, Parameter, ParamLocation,
    load_surface, parse_openapi, parse_graphql, parse_urls,
    pair_version_siblings, infer_transitions, normalize_path, resource_of,
)
from tools.mutator import Mutator, RiskClass, Mutation
from tools.impact_focus import CriticalityRouter
from tools.discovery_scheduler import (
    CoverageTracker, DiscoveryScheduler, FollowUpStep,
)
from tools.observation import (
    ObservationRecord, ObservationState, HttpObservation,
    FollowUpExperiment, FollowUpKind, RequestSpec,
)


def _record(state, *, follow_up=None):
    r = ObservationRecord(
        target="example.com", url="http://example.com/x",
        control_url="http://example.com/x", method="GET",
        bug_class="x", probe_label="x",
        candidate=HttpObservation(status=200, body="a"),
        control=HttpObservation(status=200, body="a"),
        state=state,
    )
    if follow_up is not None:
        r.follow_up = follow_up
    return r


OPENAPI_V3 = {
    "openapi": "3.0.0",
    "servers": [{"url": "https://api.example.com"}],
    "paths": {
        "/v1/users/{id}": {
            "get": {
                "operationId": "getUserV1",
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "integer", "format": "int64"}},
                    {"name": "expand", "in": "query",
                     "schema": {"type": "string", "enum": ["all", "none"]}},
                ],
            },
        },
        "/v2/users/{id}": {
            "get": {
                "operationId": "getUserV2",
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "integer", "format": "int64"}},
                ],
            },
        },
        "/v1/orders": {
            "post": {
                "operationId": "createOrder",
                "parameters": [],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "required": ["amount", "user_id"],
                        "properties": {
                            "amount": {"type": "integer"},
                            "user_id": {"type": "string", "format": "uuid"},
                            "status": {"type": "string",
                                      "enum": ["pending", "paid"]},
                        },
                    }}},
                },
            },
        },
    },
}


class TestSurfaceModelParsing(unittest.TestCase):
    def test_openapi_v3_parses_params_and_body(self):
        model = parse_openapi(OPENAPI_V3, "example.com")
        self.assertEqual(len(model.operations), 3)
        get_user = model.operation_by_id("getUserV1")
        self.assertEqual(get_user.path, "/v1/users/{id}")
        names = {p.name: p for p in get_user.params}
        self.assertEqual(names["id"].type, "integer")
        self.assertTrue(names["id"].required)
        self.assertEqual(names["expand"].enum, ["all", "none"])

        create = model.operation_by_id("createOrder")
        body_names = {p.name for p in create.params}
        self.assertIn("amount", body_names)
        self.assertIn("user_id", body_names)
        self.assertIn("status", body_names)
        status = next(p for p in create.params if p.name == "status")
        self.assertEqual(status.enum, ["pending", "paid"])
        amount = next(p for p in create.params if p.name == "amount")
        self.assertTrue(amount.required)

    def test_swagger_2_inline_parameters(self):
        spec = {
            "swagger": "2.0",
            "host": "api.example.com",
            "paths": {
                "/items": {
                    "get": {
                        "operationId": "listItems",
                        "parameters": [
                            {"name": "limit", "in": "query", "type": "integer",
                             "format": "int32"},
                        ],
                    },
                },
            },
        }
        model = parse_openapi(spec, "example.com")
        op = model.operation_by_id("listItems")
        self.assertEqual(op.params[0].type, "integer")
        self.assertEqual(model.base_urls, ["https://api.example.com"])

    def test_urls_parser_derives_params(self):
        model = parse_urls(
            ["https://example.com/api/user?id=123&page=2",
             "https://example.com/api/user/{uid}"],
            "example.com")
        get_op = next(o for o in model.operations if "id=123" not in o.operation_id)
        # The {uid} operation should carry a path parameter.
        by_id = {o.operation_id: o for o in model.operations}
        self.assertIn("GET /api/user/{uid}", by_id)
        self.assertEqual(by_id["GET /api/user/{uid}"].params[0].location.value,
                         "path")


class TestSiblingsAndTransitions(unittest.TestCase):
    def test_normalize_path_collapses_versions(self):
        self.assertEqual(normalize_path("/v1/users/{id}"),
                         "/{ver}/users/{id}")
        self.assertEqual(normalize_path("/api/v2/orders"), "/api/{ver}/orders")

    def test_version_siblings_pair(self):
        model = parse_openapi(OPENAPI_V3, "example.com")
        self.assertEqual(len(model.siblings), 1)
        group = model.siblings[0]
        self.assertEqual(set(group.operation_ids), {"getUserV1", "getUserV2"})

    def test_transitions_ordered_by_verb_priority(self):
        ops = [
            Operation(operation_id="create", method="POST", path="/orders",
                      source="urls"),
            Operation(operation_id="approve", method="POST",
                      path="/orders/approve", source="urls"),
            Operation(operation_id="cancel", method="POST",
                      path="/orders/cancel", source="urls"),
        ]
        transitions = infer_transitions(ops)
        steps = [t.step for t in sorted(transitions, key=lambda t: t.order)]
        self.assertLess(steps.index("create"), steps.index("approve"))
        self.assertLess(steps.index("approve"), steps.index("cancel"))


class TestGraphQLParsing(unittest.TestCase):
    def test_graphql_fields_and_enum_args(self):
        introspection = {
            "data": {"__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {"kind": "OBJECT", "name": "Query", "fields": [
                        {"name": "user",
                         "args": [
                             {"name": "id", "type": {"kind": "NON_NULL",
                              "ofType": {"kind": "SCALAR", "name": "ID"}}},
                             {"name": "status",
                              "type": {"kind": "ENUM", "name": "Status"}},
                         ]},
                    ]},
                    {"kind": "ENUM", "name": "Status",
                     "enumValues": [{"name": "ACTIVE"}, {"name": "DISABLED"}]},
                ],
            }},
        }
        model = parse_graphql(introspection, "example.com")
        op = model.operation_by_id("Query.user")
        self.assertEqual(op.method, "POST")
        self.assertEqual(op.path, "/graphql")
        by_name = {p.name: p for p in op.params}
        self.assertTrue(by_name["id"].required)
        self.assertEqual(by_name["id"].type, "string")
        self.assertEqual(by_name["status"].enum, ["ACTIVE", "DISABLED"])


class TestMutator(unittest.TestCase):
    def setUp(self):
        self.model = parse_openapi(OPENAPI_V3, "example.com")

    def test_boundary_values_include_type_extremes(self):
        muts = Mutator().mutations(self.model)
        get_user = [m for m in muts if m.operation_id == "getUserV1"]
        boundary = [m for m in get_user
                    if m.kind == "boundary" and m.variable == "id"]
        values = {m.mutated for m in boundary}
        self.assertIn(0, values)
        self.assertIn(2 ** 31 - 1, values)

    def test_enum_mutation_generates_out_of_range(self):
        muts = Mutator().mutations(self.model)
        expand = [m for m in muts
                  if m.operation_id == "getUserV1" and m.variable == "expand"]
        values = {m.mutated for m in expand}
        self.assertIn("all", values)
        self.assertIn("__invalid__", values)

    def test_mass_assignment_only_on_write_body(self):
        muts = Mutator().mutations(self.model)
        mass = [m for m in muts if m.kind == "mass_assignment"]
        self.assertTrue(all(m.method in ("POST", "PUT", "PATCH") for m in mass))
        self.assertTrue(any(m.operation_id == "createOrder" for m in mass))

    def test_injection_only_on_sink_params(self):
        from tools.mutator import SINK_PARAMS
        muts = Mutator().mutations(self.model)
        inj = [m for m in muts if m.kind == "injection"]
        self.assertTrue(inj)
        for m in inj:
            base = m.variable.split(".")[-1].lower()
            self.assertIn(base, SINK_PARAMS)
        self.assertTrue(any(m.variable == "user_id" for m in inj))
        # 'expand' is a plain enum, not a sink — it must never be injected.
        self.assertFalse(any(m.variable == "expand" for m in inj))

    def test_required_tamper_has_omit_and_null(self):
        muts = Mutator().mutations(self.model)
        tamper = [m for m in muts
                  if m.operation_id == "createOrder"
                  and m.kind == "required_tamper" and m.variable == "amount"]
        values = {m.mutated for m in tamper}
        self.assertIn("__omit__", values)
        self.assertIn("__null__", values)

    def test_state_and_sibling_mutations_emitted(self):
        muts = Mutator().mutations(self.model)
        self.assertTrue(any(m.kind == "state" for m in muts))
        sibling = [m for m in muts if m.kind == "sibling_differential"]
        self.assertEqual(len(sibling), 1)
        self.assertEqual(sibling[0].sibling_id, "getUserV1")

    def test_mutations_bounded_and_stable_ids(self):
        m1 = Mutator(max_total=100).mutations(self.model)
        m2 = Mutator(max_total=100).mutations(self.model)
        self.assertLessEqual(len(m1), 100)
        self.assertEqual([m.mutation_id for m in m1],
                         [m.mutation_id for m in m2])


class TestDiscoveryScheduler(unittest.TestCase):
    def setUp(self):
        self.model = parse_openapi(OPENAPI_V3, "example.com")
        self.scheduler = DiscoveryScheduler("example.com")

    def _fake_transport(self, states):
        """Return a transport that yields the given states round-robin."""
        it = iter(states)

        def transport(mutation):
            return _record(next(it))
        return transport

    def test_rank_orders_critical_focus_first(self):
        model = parse_openapi({
            "openapi": "3.0.0",
            "paths": {
                "/withdraw": {"post": {"operationId": "withdraw",
                                       "parameters": []}},
                "/public/list": {"get": {"operationId": "list",
                                         "parameters": []}},
            },
        }, "example.com")
        ranked = self.scheduler.rank(model, CoverageTracker())
        first_op = ranked[0].operation_id
        self.assertEqual(first_op, "withdraw")

    def test_allocate_prefers_untried(self):
        cov = CoverageTracker()
        all_muts = self.scheduler.rank(self.model, cov)
        # Mark the top-ranked mutation as tried; allocation must skip it first.
        tried = all_muts[0]
        cov.mark_tried(tried.key())
        allocation = self.scheduler.allocate(self.model, cov, 3)
        self.assertNotIn(tried.key(), [m.key() for m in allocation])
        self.assertEqual(len(allocation), 3)

    def test_allocate_art_deterministic_and_bounded(self):
        cov = CoverageTracker()
        a = self.scheduler.allocate(self.model, cov, 5, art=True)
        b = self.scheduler.allocate(self.model, cov, 5, art=True)
        self.assertEqual([m.mutation_id for m in a],
                         [m.mutation_id for m in b])
        self.assertEqual(len(a), 5)
        self.assertEqual(len({m.mutation_id for m in a}), 5)

    def test_allocate_art_prefers_untried(self):
        cov = CoverageTracker()
        all_muts = self.scheduler.rank(self.model, cov)
        tried = all_muts[0]
        cov.mark_tried(tried.key())
        allocation = self.scheduler.allocate(self.model, cov, 5, art=True)
        self.assertNotIn(tried.key(), [m.key() for m in allocation])
        self.assertEqual(len(allocation), 5)

    def test_allocate_art_refills_from_tried(self):
        cov = CoverageTracker()
        all_muts = self.scheduler.rank(self.model, cov)
        for m in all_muts:
            cov.mark_tried(m.key())
        allocation = self.scheduler.allocate(self.model, cov, 3, art=True)
        self.assertEqual(len(allocation), 3)
        self.assertTrue(all(cov.is_tried(m.key()) for m in allocation))

    def test_allocate_art_carries_payload_mutations(self):
        """ART allocation must select payload-bearing (injection/blind_sqli)
        mutations and embed them in the TF-IDF token space."""
        cov = CoverageTracker()
        allocation = self.scheduler.allocate(self.model, cov, 20, art=True)
        self.assertTrue(any(m.kind in ("injection", "blind_sqli")
                            for m in allocation))
        from tools.art_selector import build_payload_space
        space = build_payload_space(allocation)
        self.assertIsNotNone(space)
        self.assertGreater(space.dimension, 0)

    def test_run_signal_marks_observed_and_calls_on_signal(self):
        cov = CoverageTracker()
        called = []
        muts = self.scheduler.allocate(self.model, cov, 1)
        summary = self.scheduler.run(
            muts, self._fake_transport([ObservationState.SIGNAL]), cov,
            on_signal=lambda m, r: called.append(m.operation_id))
        self.assertEqual(summary.signals, 1)
        self.assertTrue(cov.to_dict()["observed_count"] >= 1)
        self.assertEqual(len(called), 1)

    def test_run_unknown_emits_follow_up_step(self):
        fu = FollowUpExperiment(
            kind=FollowUpKind.TIMING_CONTROL, purpose="resolve timing",
            requests=[RequestSpec(role="candidate", method="GET",
                                  url="http://example.com/x", runs=3)],
            acceptance=["median timing delta >= 0.5s"],
        )
        cov = CoverageTracker()
        muts = self.scheduler.allocate(self.model, cov, 1)
        summary = self.scheduler.run(
            muts, self._fake_transport([ObservationState.UNKNOWN]), cov)
        self.assertEqual(summary.unknowns, 1)
        self.assertEqual(len(summary.follow_ups), 0)  # no follow_up on record

    def test_follow_up_step_extracted_when_present(self):
        fu = FollowUpExperiment(
            kind=FollowUpKind.STATUS_PROBE, purpose="resolve status",
            requests=[RequestSpec(role="control", method="GET",
                                  url="http://example.com/x")],
            acceptance=["status matches control -> refuted"],
        )
        record = _record(ObservationState.UNKNOWN, follow_up=fu)
        step = DiscoveryScheduler.follow_up_step(record)
        self.assertIsInstance(step, FollowUpStep)
        self.assertEqual(step.kind, "status_probe")

    def test_run_refuted_no_follow_up(self):
        cov = CoverageTracker()
        muts = self.scheduler.allocate(self.model, cov, 1)
        summary = self.scheduler.run(
            muts, self._fake_transport([ObservationState.REFUTED]), cov)
        self.assertEqual(summary.refuted, 1)
        self.assertEqual(summary.follow_ups, [])

    def test_coverage_roundtrip(self):
        cov = CoverageTracker()
        cov.mark_tried("a|b|c")
        cov.mark_observed("a|b|c")
        reloaded = CoverageTracker.from_dict(cov.to_dict())
        self.assertTrue(reloaded.is_tried("a|b|c"))
        self.assertIn("a|b|c", reloaded.observed)

    def test_register_signal_lead_creates_lead(self):
        mutation = self.scheduler.allocate(self.model, CoverageTracker(), 1)[0]
        record = _record(ObservationState.SIGNAL)
        result = self.scheduler.register_signal_lead(mutation, record)
        # leads.py is available in this repo; creation must succeed.
        self.assertIsNotNone(result)
        self.assertIn("lead_id", result)


class TestLoadSurfaceCliHelpers(unittest.TestCase):
    def test_load_surface_merges_urls_and_openapi(self):
        with tempfile.TemporaryDirectory() as tmp:
            urls = Path(tmp) / "urls.txt"
            urls.write_text("https://example.com/health\n")
            model = load_surface(target="example.com",
                                 urls_file=str(urls))
            self.assertTrue(any(o.path == "/health" for o in model.operations))


if __name__ == "__main__":
    unittest.main()
