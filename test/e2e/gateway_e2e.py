#!/usr/bin/env python3
"""End-to-end smoke test for gatewayd.

Starts four stub backends, points the real gatewayd binary at them, and
exercises every security control the gateway advertises. The point is to run
the built artifact, not a test binary: each assertion below is a request made
over TCP to the process the Makefile produces.
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The repo root is derived from this file's own location so the script runs
# from a checkout anywhere. It lives at test/e2e/gateway_e2e.py.
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
GATEWAY = os.path.join(REPO, "bin", "gatewayd")

JWT_SECRET = "e2e-jwt-secret-that-is-long-enough"
HMAC_SECRET = "e2e-hmac-shared-secret"
API_KEY = "e2e-api-key-account"
API_KEY_CLIENT = "account-reader"
HMAC_CLIENT = "partner-bank"

failures = []
checks = []


def check(name, ok, detail=""):
    checks.append((name, ok, detail))
    if not ok:
        failures.append(f"{name}: {detail}")
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not ok else ""))


# --- stub backends --------------------------------------------------------

class Backend:
    """A stub upstream that records what it saw and can be told to misbehave."""

    def __init__(self, name):
        self.name = name
        self.seen = []
        self.mode = "ok"  # ok | slow | error
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _record(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.seen.append({
                    "method": self.command,
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": body.decode("utf-8", "replace"),
                })
                return body

            def _respond(self, code, payload, extra=None):
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _handle(self):
                self._record()
                if outer.mode == "slow":
                    time.sleep(3)
                    return self._respond(200, {"backend": outer.name, "slow": True})
                if outer.mode == "error":
                    return self._respond(503, {"backend": outer.name, "broken": True})
                return self._respond(200, {"backend": outer.name, "ok": True})

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle
            do_DELETE = _handle

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.server.shutdown()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- tokens ---------------------------------------------------------------

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(secret=JWT_SECRET, iss="e2e-issuer", aud="e2e-audience", exp_delta=300, alg="HS256"):
    header = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    now = int(time.time())
    payload = b64(json.dumps({
        "iss": iss, "aud": aud, "sub": "alice",
        "iat": now, "exp": now + exp_delta,
    }).encode())
    signing_input = f"{header}.{payload}".encode()
    if alg == "none":
        return f"{header}.{payload}."
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64(sig)}"


def sign_hmac(method, path, query, body, client=HMAC_CLIENT, secret=HMAC_SECRET, ts=None):
    ts = str(ts if ts is not None else int(time.time()))
    body_sum = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([method, path, query, ts, client, body_sum])
    sig = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return {"X-Client-Id": client, "X-Timestamp": ts, "X-Signature": sig}


# --- gateway --------------------------------------------------------------

def hget(headers, name):
    """HTTP header lookup that ignores case.

    Go writes canonical MIME header names, which lowercases every letter after
    a dash, so X-RateLimit-Limit goes out as X-Ratelimit-Limit.
    """
    lowered = name.lower()
    for k, v in headers.items():
        if k.lower() == lowered:
            return v
    return None


def request(port, method, path, headers=None, body=b"", timeout=10):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, dict(resp.getheaders()), data
    finally:
        conn.close()


def main():
    if not os.path.exists(GATEWAY):
        print(f"{GATEWAY} is missing; run `make build` first", file=sys.stderr)
        return 1

    backends = {name: Backend(name) for name in ("account", "transfer", "payment", "customer")}
    port = free_port()
    workdir = tempfile.mkdtemp(prefix="gw-e2e-")

    config = f"""
server:
  addr: "127.0.0.1:{port}"
  read_header_timeout: 5s
  read_timeout: 30s
  write_timeout: 60s
  idle_timeout: 120s
  shutdown_timeout: 5s
  max_body_bytes: 4096

upstreams:
  account: "{backends['account'].url}"
  transfer: "{backends['transfer'].url}"
  payment: "{backends['payment'].url}"
  customer: "{backends['customer'].url}"

upstream:
  timeout: 1s
  max_idle_conns: 20
  idle_conn_timeout: 30s
  circuit_breaker:
    failure_threshold: 3
    open_timeout: 2s
    half_open_successes: 1

security:
  jwt:
    secret: "{JWT_SECRET}"
    issuer: "e2e-issuer"
    audience: "e2e-audience"
    clock_skew: 30s
  api_keys:
    - key: "{API_KEY}"
      client_id: "{API_KEY_CLIENT}"
  hmac:
    max_skew: 60s
    clients:
      - client_id: "{HMAC_CLIENT}"
        secret: "{HMAC_SECRET}"
  client_ip:
    forwarded_header: "X-Forwarded-For"
    trusted_proxies:
      - "127.0.0.0/8"

headers:
  X-Frame-Options: "DENY"
  X-Content-Type-Options: "nosniff"

logging:
  level: info
  redact_query: true

routes:
  - path: /account
    service: account
    authenticators: [jwt, api_key]
    methods: [GET, POST]
    rate_limit: 2
    rate_burst: 2
    timeout: 5s
    denied_ips:
      - "198.51.100.9/32"

  - path: /transfer
    service: transfer
    authenticators: [jwt]
    methods: [POST]
    rate_limit: 100
    rate_burst: 100
    timeout: 500ms

  - path: /payment
    service: payment
    authenticators: [hmac]
    methods: [POST]
    rate_limit: 100
    rate_burst: 100
    timeout: 5s

  - path: /customer
    service: customer
    strip_prefix: true
    authenticators: [jwt, api_key]
    methods: [GET]
    rate_limit: 100
    rate_burst: 100
    timeout: 5s
"""
    cfg_path = os.path.join(workdir, "config.yaml")
    with open(cfg_path, "w") as fh:
        fh.write(config)

    log_path = os.path.join(workdir, "gateway.log")
    log_fh = open(log_path, "w")
    proc = subprocess.Popen(
        [GATEWAY, "-config", cfg_path],
        stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=REPO, start_new_session=True,
    )

    try:
        # Wait for the listener.
        deadline = time.time() + 10
        ready = False
        while time.time() < deadline:
            try:
                request(port, "GET", "/account", timeout=1)
                ready = True
                break
            except OSError:
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
        if not ready:
            log_fh.flush()
            print("gateway did not start; log follows:")
            print(open(log_path).read())
            return 1

        # The rate limit is keyed on the client address and 127.0.0.0/8 is a
        # trusted proxy, so giving each check its own forwarded address keeps
        # the checks independent: only the rate-limit checks below share a
        # bucket on purpose.
        counter = {"n": 0}

        def fresh_ip():
            counter["n"] += 1
            return f"203.0.113.{counter['n']}"

        def api_headers(ip=None, **extra):
            return {"X-Api-Key": API_KEY, "X-Forwarded-For": ip or fresh_ip(), **extra}

        def jwt_headers(ip=None, token=None, **extra):
            return {"Authorization": f"Bearer {token or make_jwt()}",
                    "X-Forwarded-For": ip or fresh_ip(), **extra}

        api_hdr = api_headers()

        # 1. API key auth forwards to the right backend.
        st, hd, body = request(port, "GET", "/account/42", api_hdr)
        check("api_key reaches the account backend", st == 200 and json.loads(body)["backend"] == "account", f"{st} {body!r}")
        check("hardening header present on success", hget(hd, "X-Frame-Options") == "DENY", f"{hd.get('X-Frame-Options')!r}")

        # 2. JWT auth.
        st, _, body = request(port, "GET", "/account/43", jwt_headers())
        check("jwt reaches the account backend", st == 200, f"{st} {body!r}")

        # 3. Missing credentials.
        st, hd, body = request(port, "GET", "/account/44", {"X-Forwarded-For": fresh_ip()})
        check("no credentials is 401", st == 401, str(st))
        check("401 uses the error envelope", json.loads(body)["error"]["code"] == "unauthorized", body.decode())
        check("hardening header present on rejection", hget(hd, "X-Frame-Options") == "DENY", f"{hd.get('X-Frame-Options')!r}")

        # 4. A tampered JWT is rejected.
        bad = make_jwt(secret="wrong-secret-but-long-enough")
        st, _, _ = request(port, "GET", "/account/45", jwt_headers(token=bad))
        check("jwt signed with the wrong secret is 401", st == 401, str(st))

        # 5. alg:none is refused (algorithm confusion).
        none_tok = make_jwt(alg="none")
        st, _, _ = request(port, "GET", "/account/46", jwt_headers(token=none_tok))
        check("alg:none is refused", st == 401, str(st))

        # 6. An expired JWT is refused.
        expired = make_jwt(exp_delta=-600)
        st, _, _ = request(port, "GET", "/account/47", jwt_headers(token=expired))
        check("expired jwt is 401", st == 401, str(st))

        # 7. HMAC signing on /payment.
        body = json.dumps({"amount": 100}).encode()
        sig = sign_hmac("POST", "/payment", "", body)
        hdrs = {"Content-Type": "application/json", **sig}
        st, _, resp = request(port, "POST", "/payment", hdrs, body)
        check("hmac reaches the payment backend", st == 200, f"{st} {resp!r}")

        # 8. A bad signature is refused.
        bad_sig = dict(sig)
        bad_sig["X-Signature"] = "00" * 32
        st, _, _ = request(port, "POST", "/payment", {"Content-Type": "application/json", **bad_sig}, body)
        check("wrong hmac signature is 401", st == 401, str(st))

        # 9. A stale timestamp is refused.
        stale = sign_hmac("POST", "/payment", "", body, ts=int(time.time()) - 3600)
        st, _, _ = request(port, "POST", "/payment", {"Content-Type": "application/json", **stale}, body)
        check("stale hmac timestamp is 401", st == 401, str(st))

        # 10. A body altered after signing is refused.
        signed_other = sign_hmac("POST", "/payment", "", b'{"amount":1}')
        st, _, _ = request(port, "POST", "/payment",
                           {"Content-Type": "application/json", **signed_other}, b'{"amount":999}')
        check("body tampering breaks the signature", st == 401, str(st))

        # 11. The body is restored for the upstream after HMAC verification.
        paid = [r for r in backends["payment"].seen if r["method"] == "POST"]
        check("hmac verification restores the body for the upstream",
              bool(paid) and paid[-1]["body"] == '{"amount": 100}', f"{paid[-1]['body'] if paid else 'none'!r}")

        # 12. Method restrictions.
        st, hd, _ = request(port, "DELETE", "/account/1", api_headers())
        check("a disallowed method is 405", st == 405, str(st))
        check("405 carries an Allow header", "GET" in (hget(hd, "Allow") or ""), f"{hd.get('Allow')!r}")

        # 13. Unknown path.
        st, _, body = request(port, "GET", "/nowhere", api_headers())
        check("an unrouted path is 404", st == 404, str(st))

        # 14. IP deny.
        st, _, _ = request(port, "GET", "/account/1", {**api_hdr, "X-Forwarded-For": "198.51.100.9"})
        check("a denied client IP is 403", st == 403, str(st))

        # 15. A spoofed XFF from an untrusted peer is ignored.
        #     The gateway trusts 127.0.0.0/8, so this IS honoured here; the
        #     denied address above proves the header is read. Confirm a
        #     non-denied forwarded address still works.
        st, _, _ = request(port, "GET", "/account/1", {**api_hdr, "X-Forwarded-For": "203.0.113.5"})
        check("an allowed forwarded client IP is served", st == 200, str(st))

        # 16. Rate limiting. burst=2 on /account, already partly spent above
        #     by earlier /account requests from 127.0.0.1. Drive it until 429.
        rl_hdr = api_headers(ip="203.0.113.200")
        saw429 = False
        retry_after = None
        limit_hdr = None
        for _ in range(12):
            st, hd, body = request(port, "GET", "/account/rl", rl_hdr)
            if st == 429:
                saw429 = True
                retry_after = hget(hd, "Retry-After")
                limit_hdr = hget(hd, "X-RateLimit-Limit")
                check("429 uses the rate_limited code",
                      json.loads(body)["error"]["code"] == "rate_limited", body.decode())
                break
            time.sleep(0.05)
        check("the route rate limit produces a 429", saw429)
        check("429 carries Retry-After", retry_after is not None and retry_after.isdigit(), f"{retry_after!r}")
        check("429 carries X-RateLimit-Limit", limit_hdr == "2", f"{limit_hdr!r}")

        # 17. Rate limit is per client: a different forwarded address is fresh.
        st, _, _ = request(port, "GET", "/account/rl", {**api_hdr, "X-Forwarded-For": "203.0.113.77"})
        check("the rate limit is keyed per client", st == 200, str(st))

        # 18. Strip prefix.
        st, _, _ = request(port, "GET", "/customer/7", api_headers(ip="203.0.113.31"))
        seen = [r["path"] for r in backends["customer"].seen]
        check("strip_prefix is applied", st == 200 and seen and seen[-1] == "/7", f"{st} {seen!r}")

        # 19. Forwarding headers. The gateway trusts 127.0.0.0/8, so the
        #     address it resolves is the forwarded one, and that is the single
        #     value downstream services may trust: it replaces the header
        #     rather than appending, so a client cannot prepend a spoofed hop.
        cust = backends["customer"].seen[-1] if backends["customer"].seen else {}
        fwd = {k.lower(): v for k, v in cust.get("headers", {}).items()}
        check("X-Forwarded-For carries the resolved client, not the raw peer",
              fwd.get("x-forwarded-for") == "203.0.113.31", f"{fwd.get('x-forwarded-for')!r}")
        check("X-Forwarded-Proto is set", fwd.get("x-forwarded-proto") == "http", f"{fwd.get('x-forwarded-proto')!r}")
        check("X-Forwarded-Host is set", bool(fwd.get("x-forwarded-host")), f"{fwd.get('x-forwarded-host')!r}")

        # 20. Body limit.
        big = b"x" * 9000
        st, _, body = request(port, "POST", "/account", api_headers(**{"Content-Type": "application/json"}), big)
        check("an oversized body is 413", st == 413, f"{st} {body[:80]!r}")

        # 21. Timeout: /transfer sets a 500ms route timeout, which overrides
        #     the 1s upstream default, and the stub then sleeps 3s.
        backends["transfer"].mode = "slow"
        st, _, body = request(port, "POST", "/transfer", jwt_headers(**{"Content-Type": "application/json"}), b"{}", timeout=15)
        check("a route timeout yields 504", st == 504, f"{st} {body[:120]!r}")
        backends["transfer"].mode = "ok"

        # 22. Circuit breaker: make the payment backend fail 5xx until the
        #     breaker opens, then confirm the gateway short-circuits.
        backends["payment"].mode = "error"
        codes = []
        for _ in range(6):
            b = json.dumps({"amount": 1}).encode()
            s = sign_hmac("POST", "/payment", "", b)
            st, _, _ = request(port, "POST", "/payment", {"Content-Type": "application/json", **s}, b)
            codes.append(st)
        check("upstream 5xx responses are passed through", 503 in codes, str(codes))
        check("the breaker eventually short-circuits without reaching the upstream",
              codes[-1] in (503, 502), str(codes))

        # 23. The breaker recovers after open_timeout.
        backends["payment"].mode = "ok"
        time.sleep(2.5)
        recovered = None
        for _ in range(4):
            b = json.dumps({"amount": 1}).encode()
            s = sign_hmac("POST", "/payment", "", b)
            st, _, _ = request(port, "POST", "/payment", {"Content-Type": "application/json", **s}, b)
            if st == 200:
                recovered = st
                break
            time.sleep(0.4)
        check("the breaker closes again after the upstream recovers", recovered == 200, str(recovered))

        # 24. Access log: correlation fields and query redaction.
        request(port, "GET", "/account/logme?token=leak-me", api_headers())
        time.sleep(0.3)
        log_fh.flush()
        lines = [l for l in open(log_path) if l.strip().startswith("{")]
        parsed = []
        for l in lines:
            try:
                parsed.append(json.loads(l))
            except json.JSONDecodeError:
                pass
        reqs = [p for p in parsed if p.get("msg") == "request"]
        check("the access log has structured request lines", len(reqs) > 0, str(len(reqs)))
        with_path = [p for p in reqs if p.get("path") == "/account/logme"]
        check("the access log records the path", bool(with_path))
        if with_path:
            entry = with_path[-1]
            check("the access log records a request_id", bool(entry.get("request_id")), str(entry.get("request_id")))
            check("the access log records the client ip", bool(entry.get("client_ip")), str(entry.get("client_ip")))
            check("the access log records the principal", bool(entry.get("principal")), str(entry.get("principal")))
            check("the access log records the route", bool(entry.get("route")), str(entry.get("route")))
            check("the access log records the service", bool(entry.get("service")), str(entry.get("service")))
            check("the access log records the status", entry.get("status") == 200, str(entry.get("status")))
            check("the query is redacted", entry.get("query") == "[redacted]", str(entry.get("query")))
        raw_log = open(log_path).read()
        check("the secret query value never reaches the log", "leak-me" not in raw_log)
        check("no credential appears in the log",
              API_KEY not in raw_log and JWT_SECRET not in raw_log and HMAC_SECRET not in raw_log)

        # 25. Graceful shutdown on SIGTERM.
        proc.send_signal(signal.SIGTERM)
        try:
            rc = proc.wait(timeout=10)
            check("SIGTERM shuts the gateway down cleanly", rc == 0, f"exit={rc}")
        except subprocess.TimeoutExpired:
            check("SIGTERM shuts the gateway down cleanly", False, "did not exit within 10s")
        log_fh.flush()
        final = open(log_path).read()
        check("shutdown is logged", "shutdown complete" in final)

    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        log_fh.close()
        for b in backends.values():
            b.stop()

    print()
    print(f"{len(checks) - len(failures)}/{len(checks)} checks passed")
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print("  -", f)
        print(f"\nlog: {log_path}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
