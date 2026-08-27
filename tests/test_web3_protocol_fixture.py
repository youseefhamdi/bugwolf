#!/usr/bin/env python3
import unittest

from tools.web3_protocol_fixture import (
    AccountAbstractionFixture,
    BridgeFixture,
)


class TestWeb3ProtocolFixture(unittest.TestCase):
    def test_account_abstraction_replay_signal(self):
        fixture = AccountAbstractionFixture("wallet")
        fixture.record_operation({"nonce": 1, "signature": "sig1", "sender": "0xA"})
        fixture.record_operation({"nonce": 1, "signature": "sig2", "sender": "0xA"})
        candidates = fixture.candidates()
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].bug_class, "account_abstraction_replay")
        self.assertEqual(candidates[0].domain, "web3")

    def test_bridge_message_replay_signal(self):
        fixture = BridgeFixture("bridge")
        fixture.record_message({"id": "m1", "chain": "l1", "nonce": 1, "claimed": False})
        fixture.record_message({"id": "m1", "chain": "l2", "nonce": 1, "claimed": False})
        candidates = fixture.candidates()
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].bug_class, "bridge_message_replay")
        self.assertEqual(candidates[0].domain, "web3")


if __name__ == "__main__":
    unittest.main()