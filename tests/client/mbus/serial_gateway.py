"""A transparent serial-to-TCP gateway, the thing an M-Bus/IP gateway is.

It opens a pty pair, starts the given serial M-Bus slave program on the pty's slave end (the
literal argument PTY in its command line is replaced by the device path), accepts one TCP
connection at a time on 127.0.0.1:<port>, and copies bytes both ways without looking at them.
It prints "LISTENING <port>" once the slave program is running and the socket is bound.

It stops, and stops the slave program with it, when its standard input closes: the test holds
the other end, so the slave cannot outlive the test even if the gateway is killed first (a
killed gateway closes the pty, and the slave program exits on the lost serial port).

Usage: python3 -I serial_gateway.py <port, 0 for any> <program> [args with PTY]...

Standard library only. It knows nothing about M-Bus, which is the point: the frames NetGet's
master reads are the slave program's own bytes.
"""
import os
import pty
import select
import socket
import subprocess
import sys
import tty


def main():
    port = int(sys.argv[1])
    master, slave = pty.openpty()
    tty.setraw(master)
    path = os.ttyname(slave)
    argv = [path if a == "PTY" else a for a in sys.argv[2:]]
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(4)
    print("LISTENING %d" % listener.getsockname()[1], flush=True)
    stdin = sys.stdin.fileno()
    conn = None
    try:
        while child.poll() is None:
            fds = [listener, master, stdin] + ([conn] if conn else [])
            ready, _, _ = select.select(fds, [], [], 0.2)
            for r in ready:
                if r == stdin:
                    if not os.read(stdin, 64):
                        return
                elif r is listener:
                    new, _ = listener.accept()
                    if conn:
                        conn.close()
                    conn = new
                elif r == master:
                    data = os.read(master, 4096)
                    if conn and data:
                        conn.sendall(data)
                else:
                    data = conn.recv(4096)
                    if not data:
                        conn.close()
                        conn = None
                    else:
                        os.write(master, data)
    finally:
        child.kill()
        child.wait()
        os.close(master)


if __name__ == "__main__":
    main()
