"""
Thin OpenSearch HTTP helper shared by every script in this repo.

Standard library only. No pip install, no virtualenv, no
externally-managed-environment argument with Homebrew's Python five minutes
before you go on stage. If `python3` runs, this repo runs.

One place that knows about auth, TLS verification, retries and error printing,
so the demo scripts stay readable and a failure on stage prints something you
can actually act on instead of a stack trace.
"""

from __future__ import annotations

import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def load_env() -> dict[str, str]:
    """Read .env (falling back to .env.example), then let real env vars win."""
    env: dict[str, str] = {}
    for name in (".env.example", ".env"):
        path = REPO_ROOT / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    env.update({k: v for k, v in os.environ.items() if k in env or k.startswith("OPENSEARCH_")})
    return env


ENV = load_env()


def _truthy(value: str | None) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class OpenSearchError(RuntimeError):
    def __init__(self, method: str, path: str, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"{method} {path} -> HTTP {status}\n{body}")


class OS:
    """Minimal OpenSearch client. Explicit about failures, quiet when things work."""

    def __init__(self, url: str | None = None):
        self.url = (url or ENV.get("OPENSEARCH_URL", "http://localhost:9200")).rstrip("/")

        self._auth_header: str | None = None
        if not _truthy(ENV.get("DISABLE_SECURITY_PLUGIN", "true")):
            user = ENV.get("OPENSEARCH_USER", "admin")
            password = ENV.get("OPENSEARCH_PASSWORD", "")
            token = b64encode(f"{user}:{password}".encode()).decode()
            self._auth_header = f"Basic {token}"

        context = ssl.create_default_context()
        if not _truthy(ENV.get("OPENSEARCH_VERIFY_TLS", "false")):
            # The demo cluster's certificate is self-signed.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # ProxyHandler({}) disables proxy auto-detection. A corporate HTTPS_PROXY
        # in the environment must not be dialled for localhost:9200.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
        )

    # -- core ---------------------------------------------------------------- #
    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        content_type: str = "application/json",
        params: dict | None = None,
        raw: bool = False,
        ok: tuple[int, ...] = (200, 201),
        timeout: int = 120,
    ):
        url = f"{self.url}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"

        if body is None:
            data = None
        elif raw or isinstance(body, (str, bytes)):
            data = body.encode() if isinstance(body, str) else body
        else:
            data = json.dumps(body).encode()

        request = urllib.request.Request(url, data=data, method=method.upper())
        request.add_header("Content-Type", content_type)
        request.add_header("Accept", "application/json")
        if self._auth_header:
            request.add_header("Authorization", self._auth_header)

        try:
            with self._opener.open(request, timeout=timeout) as response:
                status = response.status
                payload = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            payload = exc.read()
        except urllib.error.URLError as exc:
            raise OpenSearchError(method, path, 0, f"cannot reach {self.url}: {exc.reason}") from exc

        if status not in ok:
            raise OpenSearchError(method, path, status, payload.decode("utf-8", "replace")[:4000])
        if not payload:
            return {}
        try:
            return json.loads(payload)
        except ValueError:
            return payload.decode("utf-8", "replace")

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def put(self, path, body=None, **kw):
        return self.request("PUT", path, body, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body, **kw)

    def delete(self, path, **kw):
        kw.setdefault("ok", (200, 201, 404))
        return self.request("DELETE", path, **kw)

    # -- convenience --------------------------------------------------------- #
    def search(self, index: str, body: dict, **kw):
        return self.post(f"{index}/_search", body, **kw)

    def ppl(self, query: str) -> dict:
        """Run a PPL query. Requires plugins.calcite.enabled for join/lookup."""
        return self.post("_plugins/_ppl", {"query": query})

    def count(self, index: str, body: dict | None = None) -> int:
        result = self.post(f"{index}/_count", body or {"query": {"match_all": {}}}, ok=(200, 404))
        return int(result.get("count", 0)) if isinstance(result, dict) else 0

    def bulk(self, lines: list[str], *, refresh: bool = False, tally: dict | None = None) -> int:
        """Send one pre-serialised NDJSON batch. Returns the number of failures.

        Pass `tally` to accumulate failures by (error type, reason) so the caller
        can report why documents were rejected instead of only how many."""
        payload = "\n".join(lines) + "\n"
        result = self.post(
            "_bulk",
            payload,
            content_type="application/x-ndjson",
            params={"refresh": "true"} if refresh else None,
            raw=True,
        )
        if not result.get("errors"):
            return 0
        failures = [
            item for action in result["items"] for item in action.values() if item.get("error")
        ]
        if tally is None:
            for failure in failures[:3]:
                print(f"    bulk error: {json.dumps(failure['error'])[:400]}", file=sys.stderr)
            if len(failures) > 3:
                print(f"    ... and {len(failures) - 3} more", file=sys.stderr)
        else:
            for failure in failures:
                error = failure.get("error") or {}
                key = (error.get("type", "unknown"), str(error.get("reason", ""))[:180])
                tally[key] = tally.get(key, 0) + 1
        return len(failures)

    def wait_until_ready(self, timeout: int = 180) -> None:
        deadline = time.time() + timeout
        last_error = ""
        while time.time() < deadline:
            try:
                health = self.get("_cluster/health", params={"wait_for_status": "yellow", "timeout": "5s"})
                if health.get("status") in {"green", "yellow"}:
                    version = self.get("/")["version"]["number"]
                    say_ok(f"cluster '{health['cluster_name']}' is {health['status']} (OpenSearch {version})")
                    return
            except Exception as exc:  # noqa: BLE001 - we genuinely want any failure here
                last_error = str(exc)[:200]
            time.sleep(3)
        raise SystemExit(f"cluster not ready after {timeout}s at {self.url}\n  last error: {last_error}")

    def has_processor(self, name: str) -> bool:
        """True if every node ships the named ingest processor."""
        nodes = self.get("_nodes/ingest", params={"filter_path": "nodes.*.ingest.processors"})
        for node in nodes.get("nodes", {}).values():
            names = {p["type"] for p in node.get("ingest", {}).get("processors", [])}
            if name not in names:
                return False
        return True


# --------------------------------------------------------------------------- #
# output helpers — stage-legible, no colour codes that break on a projector
# --------------------------------------------------------------------------- #
def say(msg: str = "") -> None:
    print(msg, flush=True)


def say_ok(msg: str) -> None:
    print(f"  [ok]   {msg}", flush=True)


def say_warn(msg: str) -> None:
    print(f"  [warn] {msg}", flush=True)


def say_step(msg: str) -> None:
    print(f"\n=== {msg}", flush=True)


def load_json(relative_path: str) -> dict:
    return json.loads((REPO_ROOT / relative_path).read_text())


def dump(obj: Any, limit: int | None = None) -> None:
    text = json.dumps(obj, indent=2, default=str)
    if limit and len(text.splitlines()) > limit:
        text = "\n".join(text.splitlines()[:limit] + [f"  ... ({len(text.splitlines())} lines total)"])
    print(text, flush=True)
