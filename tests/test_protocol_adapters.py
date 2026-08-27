#!/usr/bin/env python3
import unittest

from tools.protocol_adapters import (
    ProtocolAdapter,
    graphql_observation,
    grpc_observation,
    websocket_observation,
)


class TestProtocolAdapters(unittest.TestCase):
    def test_graphql_observation_emits_batching_signal(self):
        obs = graphql_observation(
            endpoint="/graphql", query="query{user{id}}",
            response={"data": {"user": {"id": 1}}}, status=200,
            aliases=5, depth=4,
        )
        self.assertEqual(obs["protocol"], "graphql")
        self.assertTrue(any("aliases" in s for s in obs["signals"]))

    def test_websocket_observation_tracks_message_sequence(self):
        obs = websocket_observation(
            endpoint="wss://lab/socket", messages=[{"type": "auth"}, {"type": "data"}],
            status=101,
        )
        self.assertEqual(obs["protocol"], "websocket")
        self.assertEqual(obs["message_count"], 2)

    def test_grpc_observation_tracks_method(self):
        obs = grpc_observation(endpoint="lab:50051", method="/auth.Login",
                               status=0, trailers={"grpc-status": "0"})
        self.assertEqual(obs["protocol"], "grpc")
        self.assertEqual(obs["method"], "/auth.Login")

    def test_adapter_emits_candidates_for_signals(self):
        adapter = ProtocolAdapter("lab")
        candidates = adapter.analyze([graphql_observation(
            endpoint="/graphql", query="q", response={"data": {}}, status=200,
            aliases=8, depth=3)])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "web_api")
        self.assertEqual(candidates[0].bug_class, "graphql_abuse")


if __name__ == "__main__":
    unittest.main()