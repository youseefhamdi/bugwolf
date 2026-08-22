#!/usr/bin/env python3
import json
import unittest

from tools.data_governance import audit_requirements, classify_schema, topic_plan
from tools.pii_firewall import PIIFirewall, multilingual_rule_plans


class TestPIIFirewall(unittest.TestCase):
    def test_text_masking_consolidates_tokens_and_unmasks_in_memory(self):
        firewall = PIIFirewall(ttl_seconds=60)
        original = "Email jane@example.com and again jane@example.com; SSN 123-45-6789."
        decision = firewall.prepare_egress(original, "request-1")
        self.assertTrue(decision.allowed)
        self.assertNotIn("jane@example.com", decision.masked_payload)
        self.assertNotIn("123-45-6789", decision.masked_payload)
        self.assertEqual(decision.masked_payload.count("[[EMAIL_1]]"), 2)
        restored = firewall.vault.unmask("request-1", decision.masked_payload)
        self.assertEqual(restored, original)
        self.assertTrue(all(entity.value_hash for entity in firewall.mask_text(original, "request-2").entities))

    def test_json_field_rules_and_xml_doctype_rejection(self):
        firewall = PIIFirewall()
        masked, result = firewall.mask_json({"email": "not-an-email-but-sensitive", "note": "call jane@example.com"}, "json-1")
        self.assertTrue(masked["email"].startswith("[[EMAIL_"))
        self.assertNotIn("jane@example.com", json.dumps(masked))
        self.assertGreaterEqual(len(result.entities), 2)
        with self.assertRaises(ValueError):
            firewall.mask_xml("<!DOCTYPE foo><foo>jane@example.com</foo>", "xml-1")
        xml, _ = firewall.mask_xml("<person><email>jane@example.com</email></person>", "xml-2")
        self.assertNotIn("jane@example.com", xml)

    def test_policy_and_multilingual_plans(self):
        firewall = PIIFirewall(policy="fail_closed")
        decision = firewall.prepare_egress("normal text", "clean")
        self.assertTrue(decision.allowed)
        plans = multilingual_rule_plans()
        self.assertIn("ar", {plan["locale"] for plan in plans})
        self.assertTrue(all(plan["status"] == "plan_only" for plan in plans))


class TestDataGovernance(unittest.TestCase):
    def test_schema_classification_drives_field_audit_and_topic_tier(self):
        fields = classify_schema({"properties": {"email": {"type": "string"}, "diagnosis": {"type": "string"}, "patient_id": {"type": "string"}}})
        by_path = {field.path: field for field in fields}
        self.assertEqual(by_path["email"].classification, "restricted-pii")
        self.assertEqual(by_path["patient_id"].encryption_tier, "field-level-encryption")
        requirements = audit_requirements(fields)
        self.assertTrue(requirements["field_level_audit_required"])
        self.assertEqual(topic_plan("clinical.events", "restricted-pii").encryption, "field-level-encryption-with-per-field-keys")


if __name__ == "__main__":
    unittest.main()
