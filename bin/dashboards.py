#!/usr/bin/env python3
"""
Import the saved objects and refresh their field lists.

The refresh is the part that matters. An index pattern imported from NDJSON
arrives with no cached field list, and OpenSearch Dashboards does not always
fetch one on first use - so a panel whose KQL names a specific field
(gen_ai.agent.id, context.hash) can resolve to "match nothing" and render
"No results found" with no error anywhere. Clicking "refresh field list" in
Stack Management fixes it by hand; this does it for every pattern at once.
"""

from __future__ import annotations

import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from os_http import ENV, REPO_ROOT, say, say_ok, say_step, say_warn  # noqa: E402

DASHBOARDS = ENV.get("DASHBOARDS_URL", "http://localhost:5601").rstrip("/")
NDJSON = REPO_ROOT / "dashboards" / "saved-objects.ndjson"
META_FIELDS = ["_source", "_id", "_type", "_index", "_score"]


def call(method: str, path: str, body: bytes | None = None, content_type: str | None = None):
    request = urllib.request.Request(f"{DASHBOARDS}{path}", data=body, method=method)
    request.add_header("osd-xsrf", "true")
    if content_type:
        request.add_header("Content-Type", content_type)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=120) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
        raise RuntimeError(f"{method} {path} -> HTTP {status}: {raw.decode('utf-8', 'replace')[:500]}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"cannot reach OpenSearch Dashboards at {DASHBOARDS}: {exc.reason}\n"
                         f"  is it up?  docker compose ps")
    return json.loads(raw) if raw else {}


def import_objects() -> None:
    say_step("Importing saved objects")
    if not NDJSON.exists():
        raise SystemExit(f"{NDJSON} is missing")
    boundary = "----chasingshadows"
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="file"; filename="saved-objects.ndjson"\r\n',
        b"Content-Type: application/ndjson\r\n\r\n",
        NDJSON.read_bytes(),
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    result = call("POST", "/api/saved_objects/_import?overwrite=true", body,
                  f"multipart/form-data; boundary={boundary}")
    say_ok(f"{result.get('successCount', 0)} objects imported")
    for error in result.get("errors", []) or []:
        say_warn(f"{error.get('type')} {error.get('id')}: {json.dumps(error.get('error'))[:200]}")


def index_patterns() -> list[dict]:
    result = call("GET", "/api/saved_objects/_find?type=index-pattern&per_page=100&fields=title&fields=timeFieldName")
    return result.get("saved_objects", [])


def refresh_fields() -> None:
    say_step("Refreshing field lists")
    for obj in index_patterns():
        title = obj["attributes"].get("title", "")
        time_field = obj["attributes"].get("timeFieldName")
        query = urllib.parse.urlencode(
            [("pattern", title)] + [("meta_fields", f) for f in META_FIELDS]
        )
        try:
            fields = call("GET", f"/api/index_patterns/_fields_for_wildcard?{query}").get("fields", [])
        except RuntimeError as exc:
            say_warn(f"{title}: could not read fields - {exc}")
            continue

        if not fields:
            say_warn(f"{title}: resolves to NO fields. Nothing matches that pattern in the cluster - "
                     f"check the index or data stream exists and has documents.")
            continue

        attributes = {"fields": json.dumps(fields)}
        if time_field:
            attributes["timeFieldName"] = time_field
        call("PUT", f"/api/saved_objects/index-pattern/{obj['id']}",
             json.dumps({"attributes": attributes}).encode(), "application/json")
        named = {f["name"] for f in fields}
        interesting = [f for f in ("gen_ai.agent.id", "context.hash", "agent.pace_cv",
                                   "event.action", "url.domain") if f in named]
        say_ok(f"{title:<20s} {len(fields):>4} fields"
               + (f"   (incl. {', '.join(interesting)})" if interesting else ""))


def main() -> int:
    say(f"Chasing shadows :: dashboards -> {DASHBOARDS}")
    import_objects()
    refresh_fields()
    say_step("Done")
    say(f"  open {DASHBOARDS}/app/dashboards")
    say("  If a panel still says 'No results found', run: python3 bin/diagnose.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
