#!/usr/bin/env python3
"""
BugWolf Infrastructure Auto-Deploy v1.0.0

Auto-provisions callback infrastructure for blind/out-of-band attacks:
  - Self-hosted interactsh server (OOB DNS/HTTP/LDAP listener)
  - HTTP callback server for SSRF verification
  - DNS exfiltration listener
  - Auto-teardown after session (no lingering infra)

Supports:
  - Local mode: Start listeners on localhost + ngrok/tunnel
  - Cloud mode: Terraform EC2/Droplet with auto-provision
  - Container mode: Docker-based disposable listeners

Usage:
  python3 tools/infra_deploy.py --mode local --type http-callback \
      --target example.com --scope-file scope.json --confirm-active
  python3 tools/infra_deploy.py --type interactsh \
      --target example.com --scope-file scope.json --confirm-active
  python3 tools/infra_deploy.py --teardown abc123
  python3 tools/infra_deploy.py --list-sessions
"""

import os
import sys
import json
import time
import signal
import socket
import hashlib
import secrets
import shutil
import subprocess
import threading
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    from tools.safety import AuthorizationError, require_authorized_target
except ImportError:  # direct script execution
    from safety import AuthorizationError, require_authorized_target

try:
    from tools.evidence import redact, redact_text
except ImportError:  # direct script execution
    from evidence import redact, redact_text

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root

ROOT = workspace_root()
sys.path.insert(0, str(CODE_ROOT))

INFRA_DIR = ROOT / "state" / "infra"
INFRA_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Callback HTTP server (for SSRF verification)
# ---------------------------------------------------------------------------

class CallbackHandler(BaseHTTPRequestHandler):
    """Minimal HTTP server that logs all incoming requests.

    Used to verify SSRF, blind XSS, and other OOB vulnerabilities.
    Each request is logged with full headers, body, and source IP.
    """

    captured_requests: List[Dict] = []

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def _log_request(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        sensitive_headers = {"authorization", "cookie", "set-cookie", "x-api-key",
                             "proxy-authorization"}
        safe_headers = redact({
            key: ("[REDACTED]" if key.lower() in sensitive_headers else value)
            for key, value in self.headers.items()
        })
        body_text = body.decode("utf-8", errors="replace")
        try:
            safe_body = json.dumps(redact(json.loads(body_text)),
                                   ensure_ascii=False)[:2000]
        except (ValueError, TypeError):
            safe_body = redact_text(body_text)[:2000]
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "path": redact_text(self.path)[:4000],
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "headers": safe_headers,
            "body": safe_body,
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
        CallbackHandler.captured_requests.append(entry)

        with open(INFRA_DIR / "callback-log.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")

    def do_GET(self):
        self._log_request()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"BugWolf Callback Server v1.0.0\n")

    def do_POST(self):
        self._log_request()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}\n')

    def do_PUT(self):
        self._log_request()
        self.send_response(200)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()


class CallbackServer:
    """Manages a disposable HTTP callback server."""

    def __init__(self, port: int = 8080, bind: str = "127.0.0.1"):
        self.port = port
        self.bind = bind
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.session_id = secrets.token_hex(8)
        self.started_at: Optional[str] = None

    def start(self):
        CallbackHandler.captured_requests = []
        self.server = HTTPServer((self.bind, self.port), CallbackHandler)
        self.server.timeout = 1
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        daemon=True)
        self._thread.start()
        self.started_at = datetime.now(timezone.utc).isoformat()

        return {
            "session_id": self.session_id,
            "url": (f"http://{self._get_public_ip()}:{self.port}"
                    if self.bind not in ("127.0.0.1", "::1", "localhost")
                    else f"http://127.0.0.1:{self.port}"),
            "local_url": f"http://127.0.0.1:{self.port}",
            "port": self.port,
            "started_at": self.started_at,
        }

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def get_captured(self) -> List[Dict]:
        return CallbackHandler.captured_requests

    def get_stats(self) -> Dict:
        captured = self.get_captured()
        sources = set(c.get("source_ip") for c in captured)
        return {
            "total_requests": len(captured),
            "unique_sources": len(sources),
            "sources": list(sources),
            "last_request": captured[-1] if captured else None,
            "uptime": (datetime.now(timezone.utc) -
                       datetime.fromisoformat(self.started_at)).total_seconds()
            if self.started_at else 0,
        }

    def _get_public_ip(self) -> str:
        """Return the operator-selected bind address without external discovery."""
        # Contacting an external IP service here would be an untracked network
        # operation and could leak the operator's address. Public deployment
        # must provide its advertised address explicitly via ``bind``.
        return self.bind if self.bind not in {"0.0.0.0", "::"} else "127.0.0.1"


# ---------------------------------------------------------------------------
# Interactsh self-hosted
# ---------------------------------------------------------------------------

def start_interactsh(target: str = "", scope_file: Optional[str] = None,
                     confirm_active: bool = False) -> Dict:
    """Start a self-hosted interactsh server after authorization.

    Interactsh is an OOB interaction server supporting DNS, HTTP, SMTP, LDAP.
    Requires: interactsh-client installed (go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest)
    """
    require_authorized_target(
        target, scope_file, active=True, confirm_active=confirm_active)
    interactsh_bin = shutil.which("interactsh-client")
    if not interactsh_bin:
        return {
            "success": False,
            "error": "interactsh-client not installed. "
                     "Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        }

    # Generate a session token
    session_id = secrets.token_hex(8)
    config_dir = INFRA_DIR / "interactsh" / session_id
    config_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Start interactsh client (uses public interactsh servers by default)
        # For self-hosted, you'd run interactsh-server separately
        proc = subprocess.Popen(
            [interactsh_bin, "-json", "-o", str(config_dir / "interactsh.log")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)

        # Wait for the OOB URL to appear in output
        time.sleep(3)

        # Read the generated URL from the log
        log_file = config_dir / "interactsh.log"
        oob_url = None
        for _ in range(10):  # Wait up to 10 seconds
            if log_file.exists():
                for line in log_file.read_text().splitlines():
                    if "." in line and len(line) > 20:
                        try:
                            data = json.loads(line)
                            if "protocol" in data:
                                oob_url = data.get("full-id", "")
                                break
                        except json.JSONDecodeError:
                            pass
            if oob_url:
                break
            time.sleep(1)

        return {
            "success": True,
            "session_id": session_id,
            "oob_url": oob_url or "check interactsh log",
            "config_dir": str(config_dir),
            "pid": proc.pid,
            "start_ticks": _process_start_ticks(proc.pid),
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# DNS exfiltration listener
# ---------------------------------------------------------------------------

class DNSExfilListener:
    """Simple DNS listener for data exfiltration via DNS queries.

    Listens on UDP port 53 (requires root/sudo).
    Captures subdomain queries and reconstructs exfiltrated data.
    """

    def __init__(self, domain: str = "exfil.local", port: int = 5353):
        self.domain = domain
        self.port = port  # Use non-privileged port to avoid sudo
        self._socket: Optional[socket.socket] = None
        self._running = False
        self.captured: List[Dict] = []

    def start(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", self.port))
        self._socket.settimeout(1.0)
        self._running = True

        thread = threading.Thread(target=self._listen, daemon=True)
        thread.start()

        return {
            "listener": "dns-exfil",
            "port": self.port,
            "domain": self.domain,
        }

    def _listen(self):
        while self._running:
            try:
                data, addr = self._socket.recvfrom(4096)
                # Parse DNS query for subdomain data
                query = data[12:]  # Skip DNS header
                parts = []
                while query and query[0] != 0:
                    length = query[0]
                    parts.append(query[1:length+1].decode("ascii", errors="replace"))
                    query = query[length+1:]

                subdomain = ".".join(parts[:-2])  # Remove domain and TLD
                if subdomain:
                    self.captured.append({
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "source": addr[0],
                        "subdomain": subdomain,
                        "decoded": bytes.fromhex(subdomain.replace(".", "")).decode(
                            "utf-8", errors="replace") if len(subdomain) % 2 == 0
                        else "[non-hex data]",
                    })
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self):
        self._running = False
        if self._socket:
            self._socket.close()


# ---------------------------------------------------------------------------
# Ngrok tunnel (for exposing local callback servers)
# ---------------------------------------------------------------------------

def start_ngrok_tunnel(local_port: int, *, target: str = "",
                       scope_file: Optional[str] = None,
                       confirm_active: bool = False) -> Dict:
    """Start an ngrok tunnel only after the target authorization gate."""
    require_authorized_target(target, scope_file, active=True,
                              confirm_active=confirm_active)
    if not 1 <= int(local_port) <= 65535:
        return {"success": False, "error": "local port must be 1..65535"}
    ngrok_bin = shutil.which("ngrok")
    if not ngrok_bin:
        return {"success": False, "error": "ngrok not installed"}

    try:
        # Start ngrok in background
        proc = subprocess.Popen(
            [ngrok_bin, "http", str(local_port), "--log=stdout"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)

        # Wait for tunnel URL
        time.sleep(3)

        # Get tunnel URL from ngrok API
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels",
                                     timeout=5) as r:
            tunnels = json.loads(r.read().decode())
            public_url = tunnels["tunnels"][0]["public_url"]

        return {
            "success": True,
            "public_url": public_url,
            "local_port": local_port,
            "pid": proc.pid,
            "start_ticks": _process_start_ticks(proc.pid),
        }
    except Exception as e:
        # Do not leave an unregistered tunnel running when discovery fails.
        try:
            _terminate_owned_process(proc.pid, "ngrok")
        except UnboundLocalError:
            pass
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Session manager
# ---------------------------------------------------------------------------

@dataclass
class InfraSession:
    session_id: str
    created_at: str
    mode: str  # local, cloud, container
    resources: Dict[str, Any] = field(default_factory=dict)
    status: str = "active"  # active, teardown


def _process_start_ticks(pid: int) -> str:
    """Read Linux process start ticks to prevent PID-reuse teardown."""
    try:
        fields = Path(f"/proc/{int(pid)}/stat").read_text().split()
        return fields[21] if len(fields) > 21 else ""
    except (FileNotFoundError, PermissionError, ValueError, OSError):
        return ""


def _terminate_owned_process(pid: int, marker: str,
                             expected_start: str = "") -> bool:
    """Terminate only a recorded child with matching command and PID identity."""
    try:
        cmdline = Path(f"/proc/{int(pid)}/cmdline").read_bytes().decode(
            "utf-8", errors="replace").replace("\x00", " ")
        if marker not in cmdline:
            return False
        if expected_start and _process_start_ticks(pid) != str(expected_start):
            return False
        os.kill(int(pid), signal.SIGTERM)
        return True
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, OSError):
        return False


class InfraManager:
    """Manages disposable callback infrastructure for an authorized target."""

    def __init__(self, target: str = "", scope_file: Optional[str] = None,
                 confirm_active: bool = False):
        INFRA_DIR.mkdir(parents=True, exist_ok=True)
        self.target = target
        self.scope_file = scope_file
        self.confirm_active = confirm_active
        self._sessions: Dict[str, InfraSession] = {}
        self._callback_server: Optional[CallbackServer] = None
        self._dns_listener: Optional[DNSExfilListener] = None
        self._dns_session_id: Optional[str] = None

    def _authorize(self) -> None:
        require_authorized_target(
            self.target, self.scope_file, active=True,
            confirm_active=self.confirm_active)

    def register_process(self, session_id: str, pid: int, kind: str) -> None:
        """Attach a child PID to a session for precise teardown."""
        session = self._sessions.get(session_id)
        if not session:
            return
        session.resources.setdefault("processes", []).append({
            "pid": int(pid), "kind": kind,
            "start_ticks": _process_start_ticks(int(pid)),
        })
        self._save_session(session)

    def start_callback_server(self, port: int = 8080,
                              bind: str = "127.0.0.1") -> Dict:
        """Start an HTTP callback server for SSRF verification."""
        self._authorize()
        if self._callback_server:
            self._callback_server.stop()

        self._callback_server = CallbackServer(port=port, bind=bind)
        info = self._callback_server.start()

        session = InfraSession(
            session_id=info["session_id"],
            created_at=info["started_at"],
            mode="local",
            resources={"type": "http-callback", "info": info},
        )
        self._sessions[info["session_id"]] = session
        self._save_session(session)

        print(f"[+] Callback server started: {info['url']}")
        print(f"    Session ID: {info['session_id']}")
        return info

    def start_dns_listener(self, port: int = 5353) -> Dict:
        """Start a DNS exfiltration listener."""
        self._authorize()
        self._dns_listener = DNSExfilListener(port=port)
        info = self._dns_listener.start()

        session = InfraSession(
            session_id=f"dns-{secrets.token_hex(4)}",
            created_at=datetime.now(timezone.utc).isoformat(),
            mode="local",
            resources={"type": "dns-listener", "info": info},
        )
        self._sessions[session.session_id] = session
        self._dns_session_id = session.session_id
        info["session_id"] = session.session_id
        self._save_session(session)

        return info

    def start_interactsh(self) -> Dict:
        """Start interactsh for OOB testing."""
        self._authorize()
        result = start_interactsh(
            self.target, self.scope_file, self.confirm_active)

        if result["success"]:
            session = InfraSession(
                session_id=result["session_id"],
                created_at=datetime.now(timezone.utc).isoformat(),
                mode="local",
                resources={"type": "interactsh", "info": result},
            )
            self._sessions[result["session_id"]] = session
            self._save_session(session)

        return result

    def start_full_stack(self) -> Dict:
        """Start all listeners: HTTP callback + DNS + interactsh."""
        self._authorize()
        results = {}

        http_info = self.start_callback_server(port=8080)
        results["http_callback"] = http_info

        dns_info = self.start_dns_listener(port=5353)
        results["dns_listener"] = dns_info

        # Try interactsh
        try:
            interactsh_info = self.start_interactsh()
            results["interactsh"] = interactsh_info
        except Exception as e:
            results["interactsh"] = {"success": False, "error": str(e)}

        return results

    def get_captured(self) -> Dict:
        """Get all captured interactions across all listeners."""
        result = {}

        if self._callback_server:
            result["http_callback"] = {
                "requests": self._callback_server.get_captured(),
                "stats": self._callback_server.get_stats(),
            }

        if self._dns_listener:
            result["dns_listener"] = {
                "queries": self._dns_listener.captured,
            }

        return result

    def teardown(self, session_id: str = None):
        """Tear down only this manager's or recorded sessions' own resources."""
        print("[*] Tearing down infrastructure...")
        selected = lambda sid: session_id is None or sid == session_id

        if self._callback_server:
            callback_id = self._callback_server.session_id
            if selected(callback_id):
                stats = self._callback_server.get_stats()
                print(f"    HTTP callback: {stats['total_requests']} requests captured")
                self._callback_server.stop()
                self._callback_server = None

        if self._dns_listener and selected(self._dns_session_id):
            print(f"    DNS listener: {len(self._dns_listener.captured)} queries captured")
            self._dns_listener.stop()
            self._dns_listener = None
            self._dns_session_id = None

        # Load persisted sessions so a fresh CLI process can clean up its own
        # recorded children. Never use pkill: that can terminate another
        # operator's ngrok/interactsh process.
        sessions = dict(self._sessions)
        for data in self.list_sessions():
            try:
                sessions.setdefault(
                    data["session_id"], InfraSession(**data))
            except (KeyError, TypeError):
                continue
        for sid, session in sessions.items():
            if not selected(sid):
                continue
            resources = session.resources or {}
            process_items = list(resources.get("processes", []))
            info = resources.get("info", {})
            if isinstance(info, dict) and info.get("pid"):
                process_items.append({"pid": info["pid"],
                                      "kind": resources.get("type", ""),
                                      "start_ticks": info.get("start_ticks", "")})
            for item in process_items:
                marker = str(item.get("kind", ""))
                if marker in {"ngrok", "interactsh", "interactsh-client"}:
                    _terminate_owned_process(
                        int(item.get("pid", 0)), marker,
                        str(item.get("start_ticks", "")))
            session.status = "teardown"
            self._save_session(session)

        print("[+] Infrastructure teardown complete")

    def list_sessions(self) -> List[Dict]:
        """List all infrastructure sessions."""
        sessions = []
        for f in INFRA_DIR.glob("session-*.json"):
            data = json.loads(f.read_text())
            sessions.append(data)
        return sessions

    def _save_session(self, session: InfraSession):
        """Persist session info."""
        out = INFRA_DIR / f"session-{session.session_id}.json"
        out.write_text(json.dumps(asdict(session), indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Infrastructure Auto-Deploy")
    parser.add_argument("--mode", default="local",
                        choices=["local", "cloud", "container"],
                        help="Deployment mode")
    parser.add_argument("--type", default="http-callback",
                        choices=["http-callback", "dns-listener", "interactsh",
                                 "full-stack"],
                        help="Infrastructure type to deploy")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port for HTTP callback server")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Callback bind address (default: loopback)")
    parser.add_argument("--dns-port", type=int, default=5353,
                        help="Port for DNS listener")
    parser.add_argument("--ngrok", action="store_true",
                        help="Expose via ngrok tunnel")
    parser.add_argument("--teardown", help="Teardown session ID")
    parser.add_argument("--teardown-all", action="store_true",
                        help="Teardown all infrastructure")
    parser.add_argument("--list-sessions", action="store_true",
                        help="List active infrastructure sessions")
    parser.add_argument("--get-captured", action="store_true",
                        help="Show captured interactions")
    parser.add_argument("--target",
                        help="Authorized target for starting callback infrastructure")
    parser.add_argument("--scope-file",
                        help="Explicit authorization scope JSON")
    parser.add_argument("--confirm-active", action="store_true",
                        help="Confirm authorized active infrastructure")
    args = parser.parse_args()

    mgr = InfraManager(args.target, args.scope_file, args.confirm_active)
    starting = not (args.list_sessions or args.teardown_all or args.teardown
                    or args.get_captured)
    if args.teardown_all and not (args.target and args.scope_file and args.confirm_active):
        print("[!] --teardown-all requires --target, --scope-file, and --confirm-active",
              file=sys.stderr)
        sys.exit(2)
    if starting:
        try:
            mgr._authorize()
        except AuthorizationError as exc:
            print(f"[!] Authorization denied: {exc}", file=sys.stderr)
            sys.exit(2)

    if args.list_sessions:
        sessions = mgr.list_sessions()
        if not sessions:
            print("[*] No active infrastructure sessions")
        for s in sessions:
            print(f"  [{s['status']}] {s['session_id']} — {s['mode']} — {s['created_at']}")

    elif args.teardown_all:
        mgr.teardown()

    elif args.teardown:
        mgr.teardown(args.teardown)

    elif args.get_captured:
        captured = mgr.get_captured()
        print(json.dumps(captured, indent=2, default=str))

    elif args.type == "full-stack":
        print("[*] Starting full attack infrastructure stack...")
        results = mgr.start_full_stack()
        print(json.dumps(results, indent=2, default=str))
        print("\n[*] Press Ctrl+C to tear down")

        def cleanup(sig, frame):
            mgr.teardown()
            sys.exit(0)

        signal.signal(signal.SIGINT, cleanup)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            mgr.teardown()

    elif args.type == "http-callback":
        info = mgr.start_callback_server(port=args.port, bind=args.bind)

        if args.ngrok:
            ngrok_result = start_ngrok_tunnel(
                args.port, target=args.target, scope_file=args.scope_file,
                confirm_active=args.confirm_active)
            if ngrok_result.get("success"):
                info["ngrok_url"] = ngrok_result["public_url"]
                mgr.register_process(info["session_id"],
                                     ngrok_result["pid"], "ngrok")
                print(f"[+] Ngrok tunnel: {ngrok_result['public_url']}")

        print(f"\n[*] Callback URL: {info['url']}")
        print(f"[*] Press Ctrl+C to stop and see captured requests")

        def cleanup(sig, frame):
            stats = mgr._callback_server.get_stats() if mgr._callback_server else {}
            print(f"\n[*] Stopping... ({stats.get('total_requests', 0)} requests captured)")
            mgr.teardown()
            sys.exit(0)

        signal.signal(signal.SIGINT, cleanup)
        try:
            while True:
                time.sleep(5)
                if mgr._callback_server:
                    stats = mgr._callback_server.get_stats()
                    if stats["total_requests"] > 0:
                        last = stats["last_request"]
                        print(f"  [{stats['total_requests']}] {last['method']} "
                              f"{last['path']} from {last['source_ip']}")
        except KeyboardInterrupt:
            stats = mgr._callback_server.get_stats() if mgr._callback_server else {}
            print(f"\n[*] Stopping... ({stats.get('total_requests', 0)} requests captured)")
            mgr.teardown()

    elif args.type == "dns-listener":
        info = mgr.start_dns_listener(port=args.dns_port)
        print(f"[*] DNS exfiltration listener started on port {args.dns_port}")
        print(f"[*] Send DNS queries to: <data>.{info['domain']}")
        print(f"[*] Press Ctrl+C to stop")

        signal.signal(signal.SIGINT, lambda s, f: mgr.teardown())
        try:
            while True:
                time.sleep(5)
                if mgr._dns_listener and mgr._dns_listener.captured:
                    print(f"  [{len(mgr._dns_listener.captured)}] queries captured")
        except KeyboardInterrupt:
            mgr.teardown()

    elif args.type == "interactsh":
        result = mgr.start_interactsh()
        print(json.dumps(result, indent=2, default=str))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
