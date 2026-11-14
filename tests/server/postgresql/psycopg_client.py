# psycopg 3 over libpq, driving NetGet's PostgreSQL server through the extended query protocol.
#
# libpq is the C client psql is built on, and shares nothing with pgwire or with tokio-postgres;
# psycopg puts every parameterised statement through Parse/Bind/Describe/Execute (server-side
# binding), and with binary=True asks for every result column in binary. psql never sends
# either.
#
# Usage: python3 psycopg_client.py <port>. Prints "ok <step>" per verified step and exits
# non-zero on the first wrong answer, naming it.
import datetime
import sys

import psycopg

port = int(sys.argv[1])


def check(step, cond, detail):
    if not cond:
        print(f"FAIL {step}: {detail}", flush=True)
        sys.exit(1)
    print(f"ok {step}", flush=True)


USERS = "SELECT id, name, active, score, born, seen_at FROM users WHERE id = %s"
EXPECTED = lambda i: (i, "Ada", True, 9.5, datetime.date(1815, 12, 10),
                      datetime.datetime(2026, 11, 13, 12, 30, 0))

with psycopg.connect(host="127.0.0.1", port=port, user="netget", dbname="netget",
                     connect_timeout=30, autocommit=True) as conn:
    # Binary results: every column type the server encodes, decoded by libpq/psycopg.
    cur = conn.cursor(binary=True)
    cur.execute(USERS, (42,))
    rows = cur.fetchall()
    check("binary select", rows == [EXPECTED(42)], f"{rows!r}")
    check("description", [d.name for d in cur.description]
          == ["id", "name", "active", "score", "born", "seen_at"],
          f"{[d.name for d in cur.description]!r}")

    # Text results for the same statement and another value: the parameter reached the model.
    cur = conn.cursor()
    cur.execute(USERS, (7,))
    rows = cur.fetchall()
    check("text select", rows == [EXPECTED(7)], f"{rows!r}")

    # A string and a NULL parameter.
    cur.execute("SELECT name FROM users WHERE name = %s AND nick IS NOT DISTINCT FROM %s",
                ("Ada", None))
    rows = cur.fetchall()
    check("string and null params", rows == [("Ada",)], f"{rows!r}")

    # A write with parameters: the command tag becomes the row count.
    cur.execute("INSERT INTO users (id, name) VALUES (%s, %s)", (43, "Grace"))
    check("insert", cur.rowcount == 1, f"rowcount {cur.rowcount}")

    # An error with its SQLSTATE.
    try:
        cur.execute("SELECT * FROM nowhere WHERE x = %s", (1,))
        check("error", False, "a statement the model refused succeeded")
    except psycopg.errors.UndefinedTable as e:
        check("error", e.sqlstate == "42P01", f"{e.sqlstate} {e}")

    # A named prepared statement, executed twice with different values.
    for i in (1, 2):
        cur.execute("SELECT id FROM users WHERE id = %s", (i,), prepare=True)
        row = cur.fetchone()
        check(f"prepared {i}", row == (i,), f"{row!r}")

print("ALL OK", flush=True)
