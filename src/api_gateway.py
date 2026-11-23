"""Loopback OpenAI-compatible passthrough, independent of account and network controls."""
from __future__ import annotations

import base64
import ctypes
import http.client
import ipaddress
import io
import json
import os
import re
import secrets
import select
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import ouc_common

HOST = "127.0.0.1"
DEFAULT_PORT = 41988
WARP_PROXY_PORT = 41987
MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_RECENT = 100
IO_TIMEOUT = 30
_ROUTES = {"/v1/models": "GET", "/v1/chat/completions": "POST", "/v1/responses": "POST"}
_lock = threading.RLock()
_lifecycle = threading.RLock()
_config = None
_server = None
_thread = None
_recent = []
_stats = {"requests": 0, "errors": 0, "prompt_tokens": 0, "completion_tokens": 0,
          "total_tokens": 0, "unknown_usage": 0}


def _dpapi(data: bytes, protect: bool) -> bytes:
    class Blob(ctypes.Structure):
        _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    result = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    operation = crypt.CryptProtectData if protect else crypt.CryptUnprotectData
    operation.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(Blob)]
    operation.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if not operation(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
        raise OSError("Key protection unavailable")
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        kernel.LocalFree(result.data)


def _encode_key(value):
    if os.name == "nt":
        try:
            return {"dpapi": base64.b64encode(_dpapi(value.encode(), True)).decode("ascii")}
        except (OSError, AttributeError):
            raise RuntimeError("Windows key protection unavailable") from None
    return {"plain": value}


def _decode_key(value):
    if not isinstance(value, dict):
        raise ValueError("Invalid stored key")
    if "dpapi" in value:
        return _dpapi(base64.b64decode(value["dpapi"], validate=True), False).decode()
    if os.name == "nt":
        raise ValueError("Plaintext keys are not accepted on Windows")
    result = value.get("plain")
    if not isinstance(result, str):
        raise ValueError("Invalid stored key")
    return result


def _validate(url, key, port, via_warp):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Port must be an integer from 1 to 65535")
    if type(via_warp) is not bool:
        raise ValueError("via_warp must be a boolean")
    if key is not None and (not isinstance(key, str) or len(key) > 8192 or
                            any(ord(c) < 33 or ord(c) > 126 for c in key)):
        raise ValueError("Invalid upstream key")
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("Invalid upstream URL")
    if not url:
        return ""
    try:
        parsed = urlsplit(url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or
                parsed.username is not None or parsed.password is not None or
                "?" in url or "#" in url or "\\" in url or
                any(ord(c) < 33 or ord(c) > 126 for c in url) or
                not parsed.path.rstrip("/").endswith("/v1")):
            raise ValueError
        upstream_port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= upstream_port <= 65535:
            raise ValueError
        host = parsed.hostname.rstrip(".").lower()
        local = host == "localhost"
        try:
            local = local or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if local and (upstream_port == port or (via_warp and upstream_port == WARP_PROXY_PORT)):
            raise ValueError
    except ValueError:
        raise ValueError("Invalid upstream /v1 URL or gateway self-loop") from None
    return url.rstrip("/")


def _save(config):
    path = ouc_common.LANE_DIR / "api_gateway.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    saved = dict(config)
    for key in ("api_key", "upstream_key"):
        saved[key] = _encode_key(saved[key])
    temporary = path.with_suffix(".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            json.dump(saved, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise RuntimeError("Could not save gateway configuration") from None


def _load():
    global _config
    if _config is not None:
        return _config
    config = {"port": DEFAULT_PORT, "upstream_url": "", "upstream_key": "",
              "api_key": secrets.token_urlsafe(32), "via_warp": True}
    path = ouc_common.LANE_DIR / "api_gateway.json"
    try:
        if path.exists():
            if path.stat().st_size > 65536:
                raise ValueError
            saved = json.loads(path.read_text(encoding="utf-8"))
            saved["api_key"] = _decode_key(saved["api_key"])
            saved["upstream_key"] = _decode_key(saved["upstream_key"])
            saved["upstream_url"] = _validate(saved["upstream_url"], saved["upstream_key"],
                                               saved["port"], saved["via_warp"])
            if not isinstance(saved["api_key"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", saved["api_key"]):
                raise ValueError
            config = {key: saved[key] for key in config}
        else:
            _save(config)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise RuntimeError("Gateway configuration could not be loaded") from None
    _config = config
    return config


def get_gateway_state():
    with _lock:
        config = _load()
        return {"running": _server is not None, "base_url": f"http://{HOST}:{config['port']}/v1",
                "port": config["port"], "upstream_url": config["upstream_url"],
                "has_upstream_key": bool(config["upstream_key"]), "via_warp": config["via_warp"],
                "api_key_set": bool(config["api_key"]), "stats": dict(_stats),
                "recent": json.loads(json.dumps(_recent[-MAX_RECENT:]))}


def configure_gateway(upstream_url: str, upstream_key: str | None, port: int, via_warp: bool):
    url = _validate(upstream_url, upstream_key, port, via_warp)
    with _lifecycle, _lock:
        config = dict(_load())
        if _server is not None and port != config["port"]:
            raise ValueError("Stop gateway before changing its port")
        config.update(upstream_url=url, port=port, via_warp=via_warp)
        if upstream_key is not None:
            config["upstream_key"] = upstream_key
        _save(config)
        _config.update(config)
        return get_gateway_state()


def get_gateway_key():
    with _lock:
        return _load()["api_key"]


def rotate_gateway_key():
    with _lock:
        config = dict(_load())
        config["api_key"] = secrets.token_urlsafe(32)
        _save(config)
        _config.update(config)
        return config["api_key"]


def _usage(value):
    if not isinstance(value, dict):
        return {}
    if isinstance(value.get("response"), dict):
        value = value["response"]
    usage = value.get("usage")
    if not isinstance(usage, dict):
        return {}
    result = {}
    for target, alternate in (("prompt_tokens", "input_tokens"), ("completion_tokens", "output_tokens"),
                              ("total_tokens", "total_tokens")):
        count = usage.get(target, usage.get(alternate))
        if type(count) is int and 0 <= count <= 10**12:
            result[target] = count
    return result


class _UsageCapture:
    def __init__(self, streaming):
        self.streaming = streaming
        self.buffer = bytearray()
        self.discard = False
        self.usage = {}
        self.event = bytearray()
        self.event_discard = False

    def feed(self, chunk):
        if not self.streaming:
            if len(self.buffer) + len(chunk) <= MAX_CAPTURE_BYTES and not self.discard:
                self.buffer.extend(chunk)
            else:
                self.buffer.clear()
                self.discard = True
            return
        # Bound both lines and events; CRLF and JSON may split at any byte.
        for part in chunk.splitlines(keepends=True):
            end = part.endswith(b"\n")
            if not self.discard:
                if len(self.buffer) + len(part) <= MAX_CAPTURE_BYTES:
                    self.buffer.extend(part)
                else:
                    self.buffer.clear()
                    self.discard = True
            if end:
                if not self.discard:
                    line = bytes(self.buffer).rstrip(b"\r\n")
                    if not line:
                        if not self.event_discard and self.event:
                            self._parse(bytes(self.event))
                        self.event.clear()
                        self.event_discard = False
                    elif line.startswith(b"data:") and not self.event_discard:
                        data = line[5:]
                        if data.startswith(b" "):
                            data = data[1:]
                        if len(self.event) + len(data) + 1 <= MAX_CAPTURE_BYTES:
                            self.event.extend(data + b"\n")
                        else:
                            self.event.clear()
                            self.event_discard = True
                else:
                    self.event.clear()
                    self.event_discard = True
                self.buffer.clear()
                self.discard = False

    def _parse(self, value):
        try:
            found = _usage(json.loads(value))
            if found:
                self.usage.update(found)
        except (ValueError, UnicodeError, RecursionError):
            pass

    def finish(self):
        if not self.streaming and not self.discard:
            self._parse(bytes(self.buffer))
        return dict(self.usage)


def _record(row):
    with _lock:
        _stats["requests"] += 1
        _stats["errors"] += int(row["status"] >= 400 or not row["completed"])
        _stats["unknown_usage"] += int(not row["usage"])
        for key, count in row["usage"].items():
            _stats[key] += count
        _recent.append(row)
        del _recent[:-MAX_RECENT]
        try:
            path = ouc_common.LANE_DIR / "api_usage.jsonl"
            line = (json.dumps(row, separators=(",", ":")) + "\n").encode()
            if len(line) > MAX_LOG_BYTES:
                return
            if path.exists() and path.stat().st_size + len(line) > MAX_LOG_BYTES:
                os.replace(path, path.with_suffix(".jsonl.1"))
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "ab") as handle:
                handle.write(line)
        except OSError:
            pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler):
        if address[0] != HOST:
            raise ValueError("Gateway must bind to 127.0.0.1")
        self.connections = set()
        self.connections_lock = threading.Lock()
        self.stopping = threading.Event()
        super().__init__(address, handler)

    def handle_error(self, request, client_address):
        pass


class _Response(http.client.HTTPResponse):
    def __init__(self, sock, *args, **kwargs):
        super().__init__(sock, *args, **kwargs)
        self.fp.close()
        self.fp = io.BufferedReader(sock.makefile("rb", buffering=0), buffer_size=1)

    def begin(self):
        super().begin()
        # Keep the connection's socket owner alive so shutdown interrupts reads
        # on Windows. Every gateway request closes its connection in finally.
        self.will_close = False


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LocalGateway"
    sys_version = ""

    def log_message(self, *args):
        pass

    def __getattr__(self, name):
        if name.startswith("do_"):
            return self._handle
        raise AttributeError(name)

    def setup(self):
        super().setup()
        self.connection.settimeout(IO_TIMEOUT)

    def do_GET(self):
        self._handle()

    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_PATCH = do_GET
    do_OPTIONS = do_GET
    do_HEAD = do_GET
    do_CONNECT = do_GET
    do_TRACE = do_GET

    def _error(self, status, message):
        self._status = status
        body = json.dumps({"error": {"message": message, "type": "gateway_error"}}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self._sent = True
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        started = time.monotonic()
        self.close_connection = True
        self._sent = False
        self._status = 502
        model = None
        streaming = False
        capture = None
        complete = False
        upstream = None
        response = None
        route = self.path if self.path in _ROUTES else ""
        with self.server.connections_lock:
            self.server.connections.add(self.connection)
        try:
            with _lock:
                config = dict(_load())
            auth = self.headers.get_all("Authorization", [])
            expected = ("Bearer " + config["api_key"]).encode()
            if len(auth) != 1 or not secrets.compare_digest(auth[0].encode("utf-8"), expected):
                self._error(401, "Invalid local API key")
                return
            if "?" in self.path or "#" in self.path:
                self._error(400, "Query strings and fragments are not supported")
                return
            if not route:
                self._error(404, "Route not found")
                return
            if self.command != _ROUTES[route]:
                self._error(405, "Method not allowed")
                return
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) > 1:
                self._error(400, "Invalid request framing")
                return
            if lengths and not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
                self._error(400, "Invalid content length")
                return
            size = int(lengths[0]) if lengths else 0
            if size > MAX_BODY_BYTES:
                self._error(413, "Request body too large")
                return
            if self.command == "GET" and size:
                self._error(400, "GET body not supported")
                return
            body = self.rfile.read(size)
            if len(body) != size:
                self._error(400, "Incomplete request body")
                return
            if self.command == "POST":
                try:
                    value = json.loads(body)
                    if not isinstance(value, dict):
                        raise ValueError
                except (ValueError, UnicodeError, RecursionError):
                    self._error(400, "Expected a JSON object")
                    return
                candidate = value.get("model")
                if (isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9_./:@+-]{1,128}", candidate)
                        and not any(key and key in candidate for key in (config["api_key"], config["upstream_key"]))):
                    model = candidate
            if not config["upstream_url"]:
                self._error(503, "Configure an upstream /v1 URL first")
                return
            parsed = urlsplit(config["upstream_url"])
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            # Resolve aliases as well as literal loopback addresses before any auth is sent.
            if port == config["port"]:
                for address in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM):
                    if ipaddress.ip_address(address[4][0]).is_loopback:
                        raise OSError("Gateway self-loop")
            cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            if config["via_warp"]:
                upstream = cls(HOST, WARP_PROXY_PORT, timeout=IO_TIMEOUT)
                upstream.set_tunnel(parsed.hostname, port)
            else:
                upstream = cls(parsed.hostname, port, timeout=IO_TIMEOUT)
            upstream.response_class = _Response
            upstream.connect()
            upstream_socket = upstream.sock
            with self.server.connections_lock:
                if self.server.stopping.is_set():
                    return
                self.server.connections.add(upstream_socket)

            headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                       "Accept-Encoding": "identity", "Connection": "keep-alive"}
            if config["upstream_key"]:
                headers["Authorization"] = "Bearer " + config["upstream_key"]
            session = self.headers.get("x-opencode-session", "")
            if re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", session):
                headers["x-opencode-session"] = session
            with self.server.connections_lock:
                if self.server.stopping.is_set():
                    return
                upstream.request(self.command, parsed.path + route[3:], body=body if self.command == "POST" else None,
                                 headers=headers)
            response = upstream.getresponse()
            self._status = response.status
            streaming = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() == "text/event-stream"
            capture = _UsageCapture(streaming)
            self.send_response(response.status)
            for name in ("Content-Type", "Retry-After", "Content-Encoding"):
                value = response.getheader(name)
                if value and len(value) <= 512 and all(32 <= ord(c) <= 126 for c in value):
                    self.send_header(name, value)
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self._sent = True
            last_activity = time.monotonic()
            while not self.server.stopping.is_set():
                if response.length == 0:
                    complete = True
                    break
                if time.monotonic() - last_activity >= IO_TIMEOUT:
                    break
                readable, _, _ = select.select([self.connection, upstream_socket], [], [], .1)
                if self.connection in readable:
                    if not self.connection.recv(1, socket.MSG_PEEK):
                        break
                if upstream_socket not in readable and not getattr(upstream_socket, "pending", lambda: 0)():
                    continue
                chunk = response.read1(65536)
                if not chunk:
                    complete = True
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                capture.feed(chunk)
                last_activity = time.monotonic()
        except (OSError, http.client.HTTPException, ValueError):
            if not self._sent:
                try:
                    self._error(502, "Upstream unavailable")
                except OSError:
                    pass
        finally:
            if response is not None:
                response.close()
            if upstream is not None:
                upstream.close()
            with self.server.connections_lock:
                self.server.connections.discard(self.connection)
                if upstream is not None and 'upstream_socket' in locals():
                    self.server.connections.discard(upstream_socket)
                    upstream_socket.close()
            usage = capture.finish() if capture is not None and (complete or streaming) else {}
            _record({"timestamp": datetime.now(timezone.utc).isoformat(), "request_id": uuid.uuid4().hex,
                     "method": self.command if self.command in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "CONNECT", "TRACE") else "OTHER",
                     "route": route, "model": model, "status": self._status,
                     "duration_ms": round((time.monotonic() - started) * 1000, 2),
                     "streaming": streaming, "usage": usage, "completed": complete})


def start_gateway():
    global _server, _thread
    with _lifecycle, _lock:
        if _server is not None:
            return get_gateway_state()
        config = _load()
        try:
            server = _Server((HOST, config["port"]), _Handler)
        except OSError:
            raise RuntimeError("Could not bind local gateway port") from None
        _server = server
        _thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .1}, daemon=True,
                                   name="api-gateway")
        _thread.start()
        return get_gateway_state()


def stop_gateway():
    global _server, _thread
    with _lifecycle:
        with _lock:
            server, thread = _server, _thread
        if server is not None:
            with server.connections_lock:
                server.stopping.set()
                for connection in server.connections:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            server.shutdown()
            server.server_close()
            thread.join(2)
            with _lock:
                _server = _thread = None
        return get_gateway_state()


def main():
    start_gateway()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        stop_gateway()


if __name__ == "__main__":
    main()
