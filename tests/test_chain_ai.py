#!/usr/bin/env python3
import unittest

from tools.ai_defense import analyze_text, defense_plans
from tools.chain_analyzer import analyze_text as analyze_chain, build_chain_plans


class TestChainAnalyzer(unittest.TestCase):
    def test_sql_upload_and_deserialization_signals_create_plans(self):
        source = """
        cursor.execute("SELECT * FROM users WHERE id=" + request.args['id'])
        SELECT * INTO OUTFILE '/tmp/result' FROM users
        uploadPath = request.body.path
        path.join(root, request.body.path); writeFile(destination, content)
        cron writes uploaded file
        ObjectInputStream.readObject()
        commons-collections-3.2.1.jar
        """
        findings = analyze_chain(source, "app.java")
        categories = {item.category for item in findings}
        self.assertIn("sqli_input", categories)
        self.assertIn("db_privileged_primitive", categories)
        self.assertIn("path_input", categories)
        self.assertIn("deserialization_sink", categories)
        chains = build_chain_plans(findings)
        titles = {chain.title for chain in chains}
        self.assertIn("SQL input to database privilege boundary", titles)
        self.assertIn("Upload/path input to file-consuming component", titles)
        self.assertIn("Untrusted deserialization and runtime dependency boundary", titles)
        self.assertTrue(all(item.status == "static_signal_human_review_required" for item in findings))

    def test_db_persistence_to_render_chain_is_detected(self):
        source = """
        INSERT INTO blog_posts (title, body) VALUES ('x', '<script>')
        SELECT * FROM blog_posts
        echo $row['body']
        header('Location: ' . $row['url'])
        """
        findings = analyze_chain(source, "app.php")
        categories = {item.category for item in findings}
        self.assertIn("db_write", categories)
        self.assertIn("db_read", categories)
        self.assertIn("output_render", categories)
        self.assertIn("redirect_sink", categories)
        chains = build_chain_plans(findings)
        titles = {chain.title for chain in chains}
        self.assertIn("Database persistence to rendered output (stored XSS / 2nd-order injection)", titles)
        self.assertTrue(all(item.status == "offline_plan_only" for item in chains))

    def test_crypto_misuse_chain_is_emitted(self):
        source = """
        Cipher.getInstance('AES/ECB/PKCS5Padding')
        key = 'hardcoded-secret-key-123456'
        md5(data)
        verify=False
        """
        findings = analyze_chain(source, "crypto.py")
        categories = {item.category for item in findings}
        self.assertIn("crypto_ecb_mode", categories)
        self.assertIn("crypto_weak_hash", categories)
        self.assertIn("crypto_hardcoded_key", categories)
        self.assertIn("crypto_tls_bypass", categories)
        chains = build_chain_plans(findings)
        titles = {chain.title for chain in chains}
        self.assertIn("Crypto-API misuse chain", titles)


class TestAIDefense(unittest.TestCase):
    def test_prompt_injection_and_mcp_boundaries_generate_defense_plans(self):
        source = """
        prompt = system_prompt + user_input
        retrieved_document passed to llm.generate
        tool_call selected by model response
        tool = send_email and delete_database
        memory.write(user_content)
        token passthrough to downstream API
        MCP redirect_uri from request and stdio server
        """
        findings = analyze_text(source, "agent.py")
        categories = {item.category for item in findings}
        self.assertIn("prompt_concatenation", categories)
        self.assertIn("indirect_content", categories)
        self.assertIn("model_selected_tool", categories)
        self.assertIn("memory_persistence", categories)
        self.assertIn("token_passthrough", categories)
        self.assertIn("mcp_oauth_url", categories)
        plans = defense_plans(findings)
        plan_categories = {plan.category for plan in plans}
        self.assertIn("input_isolation", plan_categories)
        self.assertIn("tool_authorization", plan_categories)
        self.assertIn("mcp_security", plan_categories)
        self.assertTrue(all(item.status == "static_signal_human_review_required" for item in findings))
        self.assertTrue(all(plan.status == "offline_plan_only" for plan in plans))


if __name__ == "__main__":
    unittest.main()
