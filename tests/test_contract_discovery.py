"""Tests for the smart-contract discovery core (reuses CoverageTracker)."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.contract_discovery import (
    ContractSurfaceModel, ContractFunction, ContractArgument, ContractInvariant,
    ContractMutator, ContractExecutor, ContractObservation,
    ContractDiscoveryScheduler, contract_impact_verb, load_contract_spec,
)
from tools.discovery_scheduler import CoverageTracker


def _token_model() -> ContractSurfaceModel:
    return ContractSurfaceModel(
        target="Token",
        functions=[
            ContractFunction(name="deposit",
                             args=[ContractArgument(name="amount", type="uint256")],
                             roles=[], payable=True),
            ContractFunction(name="withdraw",
                             args=[ContractArgument(name="amount", type="uint256")],
                             roles=["user"]),
            ContractFunction(name="setOwner",
                             args=[ContractArgument(name="newOwner", type="address")],
                             roles=["owner"]),
        ],
        invariants=[ContractInvariant(name="solvency",
                                      description="sum(balances) == totalSupply")],
        roles=["attacker", "user", "owner"],
    )


def _token_executor():
    """A buggy token: withdraw decrements totalSupply but not the balance."""
    def deposit(state, call):
        amt = call["args"].get("amount", 0)
        balances = dict(state["balances"])
        balances[call["caller"]] = balances.get(call["caller"], 0) + amt
        return {"totalSupply": state["totalSupply"] + amt, "balances": balances}

    def withdraw(state, call):
        amt = call["args"].get("amount", 0)
        # Bug: totalSupply falls but the caller's balance is untouched.
        return {"totalSupply": state["totalSupply"] - amt,
                "balances": state["balances"]}

    def set_owner(state, call):
        return {"totalSupply": state["totalSupply"],
                "balances": state["balances"],
                "owner": call["args"].get("newOwner", state.get("owner"))}

    transitions = {"deposit": deposit, "withdraw": withdraw, "setOwner": set_owner}
    invariants = {
        "solvency": lambda s: sum(s.get("balances", {}).values()) == s["totalSupply"],
    }
    return ContractExecutor(
        initial_state={"totalSupply": 0, "balances": {}, "owner": "owner"},
        transitions=transitions, invariants=invariants)


class TestContractImpactVerb(unittest.TestCase):
    def test_verbs(self):
        self.assertEqual(contract_impact_verb("withdraw"), "withdraw")
        self.assertEqual(contract_impact_verb("transferFrom"), "transfer")
        self.assertEqual(contract_impact_verb("mint"), "create")
        self.assertEqual(contract_impact_verb("setOwner"), "impersonate")
        self.assertEqual(contract_impact_verb("balanceOf"), "read")


class TestContractMutator(unittest.TestCase):
    def setUp(self):
        self.model = _token_model()

    def test_generates_all_kinds(self):
        muts = ContractMutator().mutations(self.model)
        kinds = {m.kind for m in muts}
        self.assertEqual(kinds, {"boundary", "role", "reentrancy", "sequence"})

    def test_boundary_arg_values(self):
        muts = ContractMutator().mutations(self.model)
        withdraw_boundary = [m for m in muts
                             if m.function == "withdraw" and m.kind == "boundary"]
        values = {m.args.get("amount") for m in withdraw_boundary}
        self.assertIn(0, values)
        self.assertIn(2 ** 256 - 1, values)

    def test_role_mutations_cover_all_roles(self):
        muts = ContractMutator().mutations(self.model)
        setowner_roles = {m.caller for m in muts
                          if m.function == "setOwner" and m.kind == "role"}
        self.assertEqual(setowner_roles, {"attacker", "user", "owner"})

    def test_reentrancy_and_sequence_bounded(self):
        muts = ContractMutator(max_sequences=80).mutations(self.model)
        self.assertLessEqual(len(muts), 80)
        self.assertTrue(any(m.kind == "reentrancy" for m in muts))
        seq = [m for m in muts if m.kind == "sequence"]
        self.assertTrue(any(len(m.sequence) >= 2 for m in seq))

    def test_stable_ids(self):
        m1 = ContractMutator().mutations(self.model)
        m2 = ContractMutator().mutations(self.model)
        self.assertEqual([m.mutation_id for m in m1],
                         [m.mutation_id for m in m2])


class TestContractExecutor(unittest.TestCase):
    def setUp(self):
        self.executor = _token_executor()
        self.model = _token_model()

    def test_withdraw_breaks_solvency(self):
        muts = {m.mutation_id: m for m in ContractMutator().mutations(self.model)}
        # Find the withdraw boundary mutation with amount=1.
        m = next(m for m in muts.values()
                 if m.function == "withdraw" and m.kind == "boundary"
                 and m.args.get("amount") == 1)
        obs = self.executor.execute(m)
        self.assertTrue(obs.violated_any())
        self.assertIn("solvency", obs.violated)

    def test_deposit_holds_solvency(self):
        muts = {m.mutation_id: m for m in ContractMutator().mutations(self.model)}
        m = next(m for m in muts.values()
                 if m.function == "deposit" and m.kind == "boundary"
                 and m.args.get("amount") == 1)
        obs = self.executor.execute(m)
        self.assertFalse(obs.violated_any())
        self.assertEqual(obs.invariants["solvency"], True)

    def test_minimize_finds_single_cause(self):
        # [deposit, withdraw] with amount=3 violates; minimize should drop
        # the deposit and keep [withdraw].
        self.executor._apply  # touch private helper indirectly
        minimal = self.executor.minimize(["deposit", "withdraw"], "attacker",
                                         {"amount": 3})
        self.assertEqual(minimal, ["withdraw"])

    def test_missing_transition_records_error(self):
        from tools.contract_discovery import ContractMutation
        m = ContractMutation(mutation_id="x", function="nope",
                             sequence=["nope"], caller="attacker")
        obs = self.executor.execute(m)
        self.assertTrue(obs.error)
        self.assertFalse(obs.violated_any())


class TestContractScheduler(unittest.TestCase):
    def setUp(self):
        self.model = _token_model()
        self.executor = _token_executor()
        self.scheduler = ContractDiscoveryScheduler(self.model, self.executor)

    def test_rank_orders_withdraw_first(self):
        ranked = self.scheduler.rank(CoverageTracker())
        self.assertEqual(ranked[0].function, "withdraw")

    def test_allocate_prefers_untried(self):
        cov = CoverageTracker()
        all_muts = self.scheduler.rank(cov)
        cov.mark_tried(all_muts[0].key())
        alloc = self.scheduler.allocate(cov, 3)
        self.assertNotIn(all_muts[0].key(), [m.key() for m in alloc])

    def test_run_finds_violations_and_records_minimal(self):
        cov = CoverageTracker()
        alloc = self.scheduler.allocate(cov, 200)
        summary = self.scheduler.run(alloc, cov)
        self.assertGreaterEqual(summary.violations, 1)
        self.assertIn("solvency", summary.by_invariant)
        self.assertTrue(summary.minimal_reproducers)
        self.assertTrue(all(r["sequence"] for r in summary.minimal_reproducers))

    def test_coverage_is_the_same_tracker(self):
        # Prove the contract scheduler reuses the Web core's CoverageTracker.
        cov = CoverageTracker()
        self.scheduler.run(self.scheduler.allocate(cov, 5), cov)
        self.assertGreater(cov.to_dict()["tried_count"], 0)


class TestContractSpecLoader(unittest.TestCase):
    def test_load_spec_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "spec.json"
            p.write_text(json.dumps(_token_model().to_dict()))
            model = load_contract_spec(str(p))
            self.assertEqual(model.target, "Token")
            self.assertEqual([f.name for f in model.functions],
                             ["deposit", "withdraw", "setOwner"])

    def test_abi_coercion(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "abi.json"
            p.write_text(json.dumps({
                "name": "Token",
                "abi": [
                    {"type": "function", "name": "transfer",
                     "inputs": [{"name": "to", "type": "address"},
                                {"name": "value", "type": "uint256"}],
                     "stateMutability": "nonpayable"},
                ],
            }))
            model = load_contract_spec(str(p))
            self.assertEqual(model.functions[0].name, "transfer")
            self.assertEqual(model.functions[0].args[0].type, "address")


if __name__ == "__main__":
    unittest.main()
