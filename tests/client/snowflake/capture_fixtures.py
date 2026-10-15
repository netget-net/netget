"""Capture query responses from a running Snowflake-protocol server into fixture files.

The fixtures under fixtures/ are what decode_test.rs decodes: the `data` object of each
response, exactly as the server sent it. They were captured from fakesnow 0.11.22 (Arrow
results) and snowflake-emulator v0.0.9 (JSON results), started as install_peers.sh describes:

    python3 -I capture_fixtures.py http://127.0.0.1:<fakesnow port> fakesnow fixtures/
    python3 -I capture_fixtures.py http://127.0.0.1:<emulator port> emulator fixtures/

Standard library only, so it runs under any python3.
"""
import json
import pathlib
import sys
import urllib.request

base, server, out = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])

if server == "fakesnow":
    CREATE = (
        "CREATE TABLE notes (id INT, amount NUMBER(9,2), body VARCHAR, ok BOOLEAN, dv DATE, "
        "tv TIME, ts TIMESTAMP_NTZ, ratio FLOAT, v VARIANT, big NUMBER(38,0))"
    )
    INSERT = (
        "INSERT INTO notes VALUES (1, 123.45, 'hello', TRUE, '2026-10-14', '12:34:56', "
        "'2026-10-14 12:34:56.123456', 1.5, NULL, 3000000000), "
        "(2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)"
    )
    CAPTURE = {
        "insert": INSERT,
        "select": "SELECT * FROM notes ORDER BY id",
        "zones": "SELECT PARSE_JSON('{\"a\":[1,2],\"b\":{\"c\":null}}') AS v, "
        "TO_TIMESTAMP_TZ('2026-10-14 12:34:56.5 +02:00') AS tz, "
        "TO_TIMESTAMP_LTZ('2026-10-14 12:34:56') AS ltz, TO_BINARY('abcd','HEX') AS bin, "
        "-12.5::NUMBER(10,3) AS neg, '1969-12-31'::DATE AS before_epoch, 1 AS dup, 2 AS dup",
        "error": "SELECT nosuch FROM notes",
    }
else:
    CREATE = (
        "CREATE TABLE notes (id INTEGER, amount DECIMAL(9,2), body VARCHAR, ok BOOLEAN, "
        "ratio DOUBLE, big BIGINT)"
    )
    INSERT = (
        "INSERT INTO notes VALUES (1, 123.45, 'hello', TRUE, 1.5, 3000000000), "
        "(2, NULL, NULL, NULL, NULL, NULL)"
    )
    CAPTURE = {
        "insert": INSERT,
        "select": "SELECT * FROM notes ORDER BY id",
        "dates": "SELECT DATE '2026-10-14' AS dv",
        "error": "SELECT nosuch FROM notes",
    }


def post(path, body, token=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/snowflake")
    if token:
        req.add_header("Authorization", f'Snowflake Token="{token}"')
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


login = post(
    "/session/v1/login-request?databaseName=FIXTURES&schemaName=PUBLIC",
    {"data": {"LOGIN_NAME": "capture", "PASSWORD": "x", "SESSION_PARAMETERS": {}}},
)
token = login["data"]["token"]
post("/queries/v1/query-request", {"sqlText": CREATE}, token)
for name, sql in CAPTURE.items():
    resp = post("/queries/v1/query-request", {"sqlText": sql}, token)
    target = out / f"{server}_{name}.json"
    target.write_text(json.dumps(resp, indent=1, sort_keys=True) + "\n")
    print(target, resp.get("success"))
post("/session?delete=true", {}, token)
