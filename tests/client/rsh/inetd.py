#!/usr/bin/env python3
"""A one-service inetd for the r-service daemons: listen on HOST:PORT and, for each
connection, fork and exec the daemon with the socket as its stdin, stdout and stderr — what
inetd(8) does for a `nowait` stream service, and the only way rshd, rlogind and rexecd run.
Prints "listening" once the socket is bound.

    inetd.py HOST PORT /path/to/daemon [args...]
"""
import os
import signal
import socket
import sys

host, port, *argv = sys.argv[1:]
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((host, int(port)))
listener.listen(16)
signal.signal(signal.SIGCHLD, signal.SIG_IGN)
print("listening", flush=True)
while True:
    conn, _ = listener.accept()
    if os.fork() == 0:
        listener.close()
        for fd in (0, 1, 2):
            os.dup2(conn.fileno(), fd)
        conn.close()
        os.execv(argv[0], argv)
    conn.close()
