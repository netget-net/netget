"""Drive a Snowflake server with snowflake-connector-python, Snowflake's official Python driver.

    connector_peer.py HOST PORT USER PASSWORD SQL

Logs in (username/password), runs SQL, fetches every row through the driver's own result
decoding, and closes the connection (POST /session?delete=true). Prints one JSON object:
{"rows": [...], "description": [[name, type_code, ...]], "rowcount": n, "sfqid": "..."} or, when
the driver raises, {"error": "<class>", "errno": n, "sqlstate": "...", "msg": "..."}.

Run with -I so nothing from the working directory is imported.
"""
import json
import sys

import snowflake.connector
from snowflake.connector.constants import FIELD_ID_TO_NAME

host, port, user, password, sql = sys.argv[1:6]
try:
    conn = snowflake.connector.connect(
        user=user,
        password=password,
        account="netget",
        host=host,
        port=int(port),
        protocol="http",
        login_timeout=30,
        network_timeout=30,
    )
except snowflake.connector.errors.Error as e:
    print(json.dumps({"error": type(e).__name__, "errno": e.errno, "sqlstate": e.sqlstate, "msg": e.msg}))
    sys.exit(0)

try:
    cur = conn.cursor()
    try:
        cur.execute(sql)
        rows = [list(r) for r in cur.fetchall()]
        out = {
            "rows": rows,
            "description": [[d.name, FIELD_ID_TO_NAME[d.type_code], d.scale] for d in cur.description],
            "rowcount": cur.rowcount,
            "sfqid": cur.sfqid,
        }
    except snowflake.connector.errors.Error as e:
        out = {"error": type(e).__name__, "errno": e.errno, "sqlstate": e.sqlstate, "msg": e.msg}
finally:
    conn.close()
print(json.dumps(out, default=str))
