"""IBM's own DRDA client -- the ibm_db Python driver over IBM Data Server Driver for ODBC and
CLI -- against NetGet's Db2 server. Prints one JSON line per step for real_client_test.rs.

usage: python3 -I ibm_db_peer.py <port>
"""
import json, sys

import ibm_db

port = sys.argv[1]


def dsn(user, password, authentication=None):
    s = (
        f"DATABASE=SAMPLE;HOSTNAME=127.0.0.1;PORT={port};PROTOCOL=TCPIP;"
        f"UID={user};PWD={password};"
    )
    if authentication:
        s += f"AUTHENTICATION={authentication};"
    return s


def say(**kw):
    print(json.dumps(kw), flush=True)


def connect(step, *args):
    try:
        conn = ibm_db.connect(*args)
        say(step=step, ok=True)
        return conn
    except Exception:
        say(step=step, ok=False, message=ibm_db.conn_errormsg())
        return None


# The driver's default asks for an encrypted security mechanism, which the server cannot read.
connect("encrypted", dsn("app", "secret"), "", "")

# Cleartext user id and password (USRIDPWD), the mechanism the server implements.
conn = connect("connect", dsn("app", "secret", "SERVER"), "", "")
if conn is not None:
    for sql in ["insert into notes values (2, 'from ibm_db')", "drop table nosuch"]:
        try:
            stmt = ibm_db.exec_immediate(conn, sql)
            say(step=sql, ok=True, rows=ibm_db.num_rows(stmt))
        except Exception:
            say(step=sql, ok=False, message=ibm_db.stmt_errormsg())
    ibm_db.close(conn)

connect("intruder", dsn("intruder", "wrong", "SERVER"), "", "")
