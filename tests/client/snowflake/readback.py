"""Read a table back from a Snowflake-protocol server over a session of its own.

    readback.py connector HOST PORT DATABASE SCHEMA SQL   # snowflake-connector-python
    readback.py rest      HOST PORT DATABASE SCHEMA SQL   # the connector REST protocol by hand

`connector` is Snowflake's official Python driver (pinned by install_peers.sh), used against
fakesnow. `rest` speaks login-request/query-request with the standard library only, for
snowflake-emulator, which cannot read the gzip request bodies the official driver sends.

Prints one JSON array of rows (each an array of cells, non-JSON values as strings).
Run it with -I so nothing from the working directory is imported.
"""
import json
import sys
import urllib.request

mode, host, port, database, schema, sql = sys.argv[1:7]

if mode == "connector":
    import snowflake.connector

    conn = snowflake.connector.connect(
        user="readback",
        password="readback",
        account="netget",
        host=host,
        port=int(port),
        protocol="http",
        database=database,
        schema=schema,
        login_timeout=30,
        network_timeout=30,
    )
    try:
        cur = conn.cursor()
        cur.execute(sql)
        rows = [list(r) for r in cur.fetchall()]
    finally:
        conn.close()
else:
    base = f"http://{host}:{port}"

    def post(path, body, token=None):
        req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/snowflake")
        if token:
            req.add_header("Authorization", f'Snowflake Token="{token}"')
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    login = post(
        f"/session/v1/login-request?databaseName={database}&schemaName={schema}",
        {"data": {"LOGIN_NAME": "readback", "PASSWORD": "readback", "SESSION_PARAMETERS": {}}},
    )
    token = login["data"]["token"]
    resp = post("/queries/v1/query-request", {"sqlText": sql}, token)
    if not resp.get("success"):
        sys.exit(f"readback query failed: {resp}")
    rows = resp["data"].get("rowset") or []
    post("/session?delete=true", {}, token)

print(json.dumps(rows, default=str))
