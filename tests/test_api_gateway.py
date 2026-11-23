"""Gateway tests use temporary state and loopback fake servers only."""
from __future__ import annotations

import http.client
import importlib.util
import json
import select
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import ouc_common


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FakeUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append((self.command, self.path, dict(self.headers), body))
        self.send_response(self.server.status)
        self.send_header("Content-Type", self.server.content_type)
        if self.server.status == 302:
            self.send_header("Location", self.server.redirect)
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for chunk in self.server.chunks:
                self.wfile.write(chunk)
                self.wfile.flush()
                if self.server.gate is not None:
                    self.server.first_chunk.set()
                    self.server.gate.wait(3)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lane = mock.patch.object(ouc_common, "LANE_DIR", Path(self.tmp.name))
        self.lane.start()
        spec = importlib.util.spec_from_file_location(
            "gateway_under_test", Path(__file__).resolve().parent.parent / "src" / "api_gateway.py"
        )
        self.gateway = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.gateway)
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstream)
        self.upstream.requests = []
        self.upstream.status = 200
        self.upstream.content_type = "application/json"
        self.upstream.chunks = [b'{"object":"list","data":[]}']
        self.upstream.gate = None
        self.upstream.first_chunk = threading.Event()
        self.upstream.redirect = "http://127.0.0.1:1/v1/models"
        self.thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.thread.start()
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.upstream.server_port}/v1"

    def tearDown(self):
        if self.upstream.gate is not None:
            self.upstream.gate.set()
        self.gateway.stop_gateway()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.thread.join(3)
        self.lane.stop()
        self.tmp.cleanup()

    def start(self, url=None, key="upstream-secret", via_warp=False):
        self.gateway.configure_gateway(self.url if url is None else url, key, self.port, via_warp)
        return self.gateway.start_gateway()

    def request(self, method="GET", path="/v1/models", body=None, key=True, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        request_headers = dict(headers or {})
        if key is not False:
            request_headers["Authorization"] = "Bearer " + (
                self.gateway.get_gateway_key() if key is True else key
            )
        conn.request(method, path, body=body, headers=request_headers)
        response = conn.getresponse()
        result = response.status, response.read(), dict(response.getheaders())
        conn.close()
        return result

    def logs(self):
        deadline = time.monotonic() + 2
        path = Path(self.tmp.name) / "api_usage.jsonl"
        while time.monotonic() < deadline:
            if path.exists():
                rows = [json.loads(line) for line in path.read_text().splitlines()]
                if rows:
                    return rows
            time.sleep(.01)
        self.fail("gateway did not write request metadata")

    def test_defaults_unconfigured_and_auth_required_even_for_unknown_routes(self):
        state = self.gateway.get_gateway_state()
        self.assertEqual(state["upstream_url"], "")
        self.assertEqual(state["port"], 41988)
        self.assertTrue(state["via_warp"])
        self.start(url="", key="")
        self.assertEqual(self.request(key=False)[0], 401)
        self.assertEqual(self.request(key="wrong")[0], 401)
        self.assertEqual(self.request(path="/v1/unknown", key=False)[0], 401)
        self.assertEqual(self.request()[0], 503)
        self.assertEqual(self.upstream.requests, [])

    def test_route_allowlist_query_rejection_and_key_substitution(self):
        self.start()
        status, body, _ = self.request(headers={"X-Api-Key": "never-forward"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["object"], "list")
        method, path, headers, body = self.upstream.requests[-1]
        self.assertEqual((method, path), ("GET", "/v1/models"))
        self.assertEqual(headers["Authorization"], "Bearer upstream-secret")
        self.assertNotIn("X-Api-Key", headers)
        for method, path, expected in [
            ("GET", "/v1/chat/completions", 405),
            ("POST", "/v1/models", 405),
            ("DELETE", "/v1/models", 405),
            ("GET", "/v1/anything", 404),
            ("GET", "/v1/models?secret=hidden", 400),
            ("GET", "/v1/models#hidden", 400),
        ]:
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path, body=b"{}" if method == "POST" else None)[0], expected)
        self.assertEqual(len(self.upstream.requests), 1)

    def test_post_passthrough_and_nonstream_usage(self):
        self.start()
        answer = {"usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}}
        self.upstream.chunks = [json.dumps(answer).encode()]
        body = b'{"model":"router/model-a","messages":[{"role":"user","content":"PRIVATE PROMPT"}]}'
        status, received, _ = self.request("POST", "/v1/chat/completions", body)
        self.assertEqual((status, received), (200, self.upstream.chunks[0]))
        self.assertEqual(self.upstream.requests[-1][3], body)
        rows = self.logs()
        self.assertEqual(rows[-1]["model"], "router/model-a")
        self.assertEqual(rows[-1]["usage"], answer["usage"])
        self.assertFalse(rows[-1]["streaming"])
        for secret in ("PRIVATE PROMPT", "upstream-secret", self.gateway.get_gateway_key()):
            self.assertNotIn(secret, json.dumps(self.gateway.get_gateway_state()))
            self.assertNotIn(secret, json.dumps(rows))

    def test_responses_passthrough_usage_mapping(self):
        self.start(key="")
        self.upstream.chunks = [b'{"usage":{"input_tokens":4,"output_tokens":6,"total_tokens":10}}']
        self.assertEqual(self.request("POST", "/v1/responses", b'{"model":"m","input":"hi"}')[0], 200)
        self.assertNotIn("Authorization", self.upstream.requests[-1][2])
        self.assertEqual(self.logs()[-1]["usage"], {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10})

    def test_stream_delivers_before_eof_and_parses_split_usage(self):
        self.start()
        self.upstream.content_type = "text/event-stream"
        self.upstream.chunks = [b'data: {"choices":[]}\n\n', b'data: {"usage":{"prompt_to', b'kens":3,"completion_tokens":2,"total_tokens":5}}\r\n\r\ndata: [DONE]\n\n']
        self.upstream.gate = threading.Event()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            conn.request("POST", "/v1/chat/completions", b'{"model":"m","stream":true}',
                         {"Authorization": "Bearer " + self.gateway.get_gateway_key()})
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            first = response.read(len(self.upstream.chunks[0]))
            self.assertEqual(first, self.upstream.chunks[0])
            self.upstream.gate.set()
            self.assertEqual(first + response.read(), b"".join(self.upstream.chunks))
        finally:
            self.upstream.gate.set()
            conn.close()
        row = self.logs()[-1]
        self.assertTrue(row["streaming"])
        self.assertEqual(row["usage"]["total_tokens"], 5)

    def test_upstream_error_preserved_and_redirect_not_followed(self):
        self.start()
        self.upstream.status = 429
        self.upstream.chunks = [b'{"error":{"message":"capacity"}}']
        status, body, _ = self.request()
        self.assertEqual((status, body), (429, self.upstream.chunks[0]))
        self.upstream.status = 302
        self.assertEqual(self.request()[0], 302)
        self.assertEqual(len(self.upstream.requests), 2)

    def test_failed_connect_is_generic_and_warp_never_falls_back(self):
        self.start(via_warp=True)
        with mock.patch.object(self.gateway, "WARP_PROXY_PORT", free_port()):
            status, body, _ = self.request()
        self.assertEqual(status, 502)
        self.assertEqual(self.upstream.requests, [])
        self.assertNotIn(b"secret", body)
        self.assertNotIn(b"ConnectionRefused", body)

    def test_config_validation_is_atomic(self):
        self.start()
        invalid = ["ftp://host/v1", "file:///v1", "http://user:pass@host/v1", "http://host/v1?q=x",
                   "http://host/v1#x", "http://host", "http://host/v1/extra", "http://host:bad/v1",
                   f"http://127.0.0.1:{self.port}/v1", f"http://localhost:{self.port}/v1",
                   f"http://[::1]:{self.port}/v1", "http://host/v1?", "http://host/v1#", "http://host\\evil/v1"]
        invalid += ["http://host:0/v1", f"http://[::ffff:127.0.0.1]:{self.port}/v1"]
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.gateway.configure_gateway(url, "new-key", self.port, False)
        for port in (0, 65536, -1, True, "41988"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.gateway.configure_gateway(self.url, None, port, False)
        for key in ("bad\r\nkey", 123):
            with self.assertRaises(ValueError):
                self.gateway.configure_gateway(self.url, key, self.port, False)
        with self.assertRaises(ValueError):
            self.gateway.configure_gateway(self.url, None, free_port(), False)
        self.assertEqual(self.gateway.get_gateway_state()["upstream_url"], self.url)
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(self.upstream.requests[-1][2]["Authorization"], "Bearer upstream-secret")

    def test_key_rotation_persistence_and_explicit_clear(self):
        self.start()
        original = self.gateway.get_gateway_key()
        self.gateway.configure_gateway(self.url, None, self.port, False)
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(self.upstream.requests[-1][2]["Authorization"], "Bearer upstream-secret")
        rotated = self.gateway.rotate_gateway_key()
        self.assertNotEqual(original, rotated)
        self.assertGreaterEqual(len(rotated), 32)
        self.assertEqual(self.request(key=original)[0], 401)
        self.assertEqual(self.request(key=rotated)[0], 200)
        self.gateway.configure_gateway(self.url, "", self.port, False)
        self.assertFalse(self.gateway.get_gateway_state()["has_upstream_key"])
        self.gateway.stop_gateway()
        self.gateway._config = None
        self.assertEqual(self.gateway.get_gateway_key(), rotated)
        self.assertFalse(self.gateway.get_gateway_state()["has_upstream_key"])
        data = json.loads((Path(self.tmp.name) / "api_gateway.json").read_text())
        self.assertNotIn("upstream-secret", json.dumps(data))

    def test_body_limit_and_bad_json_never_reach_upstream(self):
        self.start()
        with mock.patch.object(self.gateway, "MAX_BODY_BYTES", 16):
            self.assertEqual(self.request("POST", "/v1/responses", b"x" * 17)[0], 413)
        self.assertEqual(self.request("POST", "/v1/responses", b"not-json")[0], 400)
        self.assertEqual(self.request("POST", "/v1/responses", b"[]")[0], 400)
        self.assertEqual(self.request("POST", "/v1/responses", b"{}", headers={"Transfer-Encoding": "chunked"})[0], 400)
        self.assertEqual(self.upstream.requests, [])

    def test_prefixed_v1_base_and_allowlisted_session_header(self):
        self.start(url=self.url.replace("/v1", "/provider/openai/v1"))
        self.assertEqual(self.request(headers={"x-opencode-session": "session-123", "Cookie": "secret"})[0], 200)
        self.assertEqual(self.upstream.requests[-1][1], "/provider/openai/v1/models")
        headers = {key.lower(): value for key, value in self.upstream.requests[-1][2].items()}
        self.assertEqual(headers["x-opencode-session"], "session-123")
        self.assertNotIn("cookie", headers)

    def test_unknown_usage_and_unknown_http_method_are_safe(self):
        self.start()
        self.assertEqual(self.request(method="CUSTOM", key=False)[0], 401)
        self.assertEqual(self.request(method="CUSTOM")[0], 405)
        self.assertEqual(self.request()[0], 200)
        rows = self.logs()
        deadline = time.monotonic() + 2
        while len(rows) < 3 and time.monotonic() < deadline:
            time.sleep(.01)
            rows = self.logs()
        state = self.gateway.get_gateway_state()
        self.assertEqual(state["stats"]["unknown_usage"], 3)
        self.assertEqual(rows[-1]["usage"], {})
        self.assertEqual(rows[0]["method"], "OTHER")

    def test_sse_multiline_usage_is_bounded_and_ignores_invalid_events(self):
        capture = self.gateway._UsageCapture(True)
        chunks = [b'data: {"response":\r', b'\ndata: {"usage":{"input_tokens":8,\n',
                  b'data: "output_tokens":2,"total_tokens":10}}}\n\n', b'data: invalid\n\n']
        for chunk in chunks:
            capture.feed(chunk)
        self.assertEqual(capture.finish(), {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10})
        with mock.patch.object(self.gateway, "MAX_CAPTURE_BYTES", 100):
            capture.feed(b"data: " + b"x" * 1000)
            self.assertLessEqual(len(capture.buffer), 100)
            capture.feed(b'\n\ndata: {"usage":{"total_tokens":12}}\n\n')
            self.assertEqual(capture.finish()["total_tokens"], 12)

    def test_nonloopback_bind_and_occupied_port_are_rejected(self):
        with self.assertRaises(ValueError):
            self.gateway._Server(("0.0.0.0", self.port), self.gateway._Handler)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", self.port))
            sock.listen()
            self.gateway.configure_gateway(self.url, None, self.port, False)
            with self.assertRaises(RuntimeError):
                self.gateway.start_gateway()
        self.assertFalse(self.gateway.get_gateway_state()["running"])

    def test_windows_dpapi_and_plaintext_config_fail_closed(self):
        with mock.patch.object(self.gateway.os, "name", "nt"), mock.patch.object(
            self.gateway, "_dpapi", side_effect=OSError("sensitive failure")
        ):
            with self.assertRaisesRegex(RuntimeError, "^Windows key protection unavailable$"):
                self.gateway.get_gateway_key()
            self.assertFalse((Path(self.tmp.name) / "api_gateway.json").exists())
            with self.assertRaises(ValueError):
                self.gateway._decode_key({"plain": "secret"})

    def test_corrupt_config_fails_closed(self):
        self.start()
        path = Path(self.tmp.name) / "api_gateway.json"
        if sys.platform != "win32":
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.gateway.stop_gateway()
        path.write_text('{"upstream_key":"sensitive-secret"}')
        self.gateway._config = None
        with self.assertRaisesRegex(RuntimeError, "^Gateway configuration could not be loaded$"):
            self.gateway.start_gateway()
        self.gateway._config = {"port": self.port, "upstream_url": "", "upstream_key": "", "api_key": "x" * 32, "via_warp": True}

    def test_cli_stops_gateway_on_keyboard_interrupt(self):
        with mock.patch.object(self.gateway, "start_gateway") as start, mock.patch.object(
            self.gateway, "stop_gateway"
        ) as stop, mock.patch.object(threading.Event, "wait", side_effect=KeyboardInterrupt):
            self.gateway.main()
        start.assert_called_once_with()
        stop.assert_called_once_with()

    def test_stop_during_connect_prevents_later_credential_send(self):
        self.start()
        entered, release = threading.Event(), threading.Event()
        original = http.client.HTTPConnection.connect

        def delayed(connection):
            entered.set()
            release.wait(3)
            return original(connection)

        with mock.patch.object(http.client.HTTPConnection, "connect", delayed):
            client_socket = socket.create_connection(("127.0.0.1", self.port))
            client_socket.sendall(("GET /v1/models HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " +
                                   self.gateway.get_gateway_key() + "\r\n\r\n").encode())
            self.assertTrue(entered.wait(2))
            self.gateway.stop_gateway()
            release.set()
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                with self.gateway._lock:
                    if self.gateway._stats["requests"] >= 1:
                        break
                time.sleep(.01)
            client_socket.close()
        self.assertEqual(self.upstream.requests, [])

    def test_selected_connect_proxy_cannot_be_upstream(self):
        self.gateway.get_gateway_key()
        with self.assertRaises(ValueError):
            self.gateway.configure_gateway("http://127.0.0.1:41987/v1", "", self.port, True)

    def test_connect_proxy_is_used_for_http_without_fallback(self):
        seen = []

        class ConnectProxy(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_CONNECT(proxy):
                seen.append((proxy.path, dict(proxy.headers)))
                with socket.create_connection(("127.0.0.1", self.upstream.server_port), timeout=3) as remote:
                    proxy.send_response(200)
                    proxy.end_headers()
                    while True:
                        readable, _, _ = select.select([proxy.connection, remote], [], [], 3)
                        if not readable:
                            return
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            (remote if source is proxy.connection else proxy.connection).sendall(data)

        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ConnectProxy)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            self.start(via_warp=True)
            with mock.patch.object(self.gateway, "WARP_PROXY_PORT", proxy.server_port):
                self.assertEqual(self.request()[0], 200)
            self.assertEqual(seen[0][0], f"127.0.0.1:{self.upstream.server_port}")
            self.assertNotIn("Authorization", seen[0][1])
            self.assertEqual(self.upstream.requests[-1][2]["Authorization"], "Bearer upstream-secret")
        finally:
            proxy.shutdown()
            proxy.server_close()
            thread.join(3)

    def test_client_disconnect_cancels_idle_upstream(self):
        self.start()
        self.upstream.content_type = "text/event-stream"
        self.upstream.gate = threading.Event()
        self.upstream.chunks = [b'data: {"choices":[]}\n\n']
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        conn.request("POST", "/v1/chat/completions", b'{"stream":true}',
                     {"Authorization": "Bearer " + self.gateway.get_gateway_key()})
        response = conn.getresponse()
        response.read(len(self.upstream.chunks[0]))
        response.fp.raw._sock.shutdown(socket.SHUT_RDWR)
        response.close()
        conn.close()
        self.assertTrue(self.logs()[-1]["streaming"])
        self.assertEqual(self.logs()[-1]["usage"], {})

    def test_upstream_timeout_and_duplicate_auth(self):
        self.start()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        conn.putrequest("GET", "/v1/models")
        for _ in range(2):
            conn.putheader("Authorization", "Bearer " + self.gateway.get_gateway_key())
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 401)
        response.read()
        conn.close()
        self.assertEqual(self.upstream.requests, [])
        self.upstream.gate = threading.Event()
        self.upstream.chunks = [b'partial']
        with mock.patch.object(self.gateway, "IO_TIMEOUT", .2):
            status, body, _ = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(body, b"partial")

    def test_loopback_only_idempotent_lifecycle_and_log_rotation(self):
        state = self.start()
        self.assertEqual(state["base_url"], f"http://127.0.0.1:{self.port}/v1")
        self.assertEqual(self.gateway._server.server_address[0], "127.0.0.1")
        self.assertTrue(self.gateway.start_gateway()["running"])
        with mock.patch.object(self.gateway, "MAX_LOG_BYTES", 700), mock.patch.object(self.gateway, "MAX_RECENT", 3):
            for _ in range(7):
                self.assertEqual(self.request()[0], 200)
            deadline = time.monotonic() + 2
            while self.gateway.get_gateway_state()["stats"]["requests"] < 7 and time.monotonic() < deadline:
                time.sleep(.01)
            state = self.gateway.get_gateway_state()
            self.assertLessEqual(len(state["recent"]), 3)
            self.assertEqual(state["stats"]["requests"], 7)
            for path in Path(self.tmp.name).glob("api_usage.jsonl*"):
                self.assertLessEqual(path.stat().st_size, 700)
        self.assertFalse(self.gateway.stop_gateway()["running"])
        self.assertFalse(self.gateway.stop_gateway()["running"])


if __name__ == "__main__":
    unittest.main()
