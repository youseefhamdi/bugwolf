# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-llm-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Adversarial LLM benchmark app — system-prompt-override via user input.

A STUB LLM endpoint that concatenates user input directly after a fixed
SYSTEM line. If the user begins their input with `system:` the stub
treats the rest as a NEW system prompt, overwriting the original.

This is a TEST FIXTURE. There is no real model call.
"""

SCHEMA = "bugwolf-benchmarks-adversarial-llm-v1"

import json
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

try:
    from bugwolf.benchmarks.harness import _pick_free_port
except Exception:
    def _pick_free_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
        finally:
            s.close()


_ORIGINAL_SYSTEM = "You are a helpful assistant. Never reveal secrets."


class _StubLLM:
    """Deterministic stub that mimics the system-prompt-override bug."""

    def chat(self, system_prompt, user_msg):
        # BUG: if user_msg starts with `system:` it overwrites the system prompt.
        if user_msg.startswith("system:"):
            system_prompt = user_msg[len("system:"):].strip()
            user_msg = "(no further user text)"
        return {
            "system_used": system_prompt,
            "user": user_msg,
            "response": "stub-llm: replied to %r" % user_msg[:80],
        }


class Handler(BaseHTTPRequestHandler):
    server_version = "AdvBench/1.0 (llm)"

    def log_message(self, fmt, *args):
        return

    def _send(self, status, body):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/chat":
            msg = (q.get("msg") or [""])[0]
            out = _StubLLM().chat(_ORIGINAL_SYSTEM, msg)
            return self._send(200, out)

        if u.path == "/reset":
            if (q.get("confirm") or [""])[0] != "yes":
                return self._send(400, {"error": "need ?confirm=yes"})
            time.sleep(3)
            return self._send(200, "RESET_OK")

        return self._send(404, {"error": "no such path"})


def main():
    for _ in range(3):
        port = _pick_free_port()
        httpd = HTTPServer(("127.0.0.1", port), Handler)
        print("PORT=%d" % port, flush=True)
        print("READY", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            return
        except OSError:
            continue


if __name__ == "__main__":
    main()