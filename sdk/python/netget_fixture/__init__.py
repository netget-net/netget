"""Run NetGet as a mock service inside a Python test suite.

Standard library only. ``NetGet`` starts the ``netget`` binary on a ``.netget`` file or an
inline list of actions, waits until every server it was asked for is listening, and exposes
the addresses they actually bound -- so a configuration can use ``"port": 0`` and never race
another test for a port. Leaving the ``with`` block (or calling ``stop()``) ends the process
and removes its working directory.

    from netget_fixture import NetGet

    ECHO = {
        "type": "open_server", "protocol": "tcp", "port": 0, "instruction": "echo",
        "event_handlers": [{
            "event_pattern": "tcp_data_received",
            "handler": {"type": "static", "actions": [
                {"type": "send_tcp_data", "data": "{{event.data}}"}]},
        }],
    }

    with NetGet(actions=[ECHO], no_model=True) as netget:
        host, port = netget.address("tcp")

Readiness comes from NetGet's ``--ready-file``: written atomically once every server is
bound and every client connected. If NetGet exits first, ``NetGetError`` carries its stderr.

The binary is ``binary=`` if given, else ``$NETGET_BIN``, else ``netget`` on ``PATH``.

For pytest, enable the plugin (``-p netget_fixture.pytest_plugin`` or
``pytest_plugins = ["netget_fixture.pytest_plugin"]`` in the root ``conftest.py``) and use the
``netget`` fixture: ``netget(actions=[...])`` starts one, stopped when the test ends.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time

__all__ = ["NetGet", "NetGetError", "Server", "Client"]

#: Points NetGet's model at a closed port, so an event no handler matches fails closed
#: instead of reaching whatever model runs on this machine.
CLOSED_MODEL_URL = "http://127.0.0.1:1"


class NetGetError(RuntimeError):
    """NetGet could not be started, exited before it was ready, or never became ready."""

    def __init__(self, message, stderr=""):
        super().__init__(f"{message}\n--- netget stderr ---\n{stderr}" if stderr else message)
        self.stderr = stderr


class Server:
    """One server from the readiness report."""

    def __init__(self, entry):
        self.id = entry.get("id")
        self.protocol = entry.get("protocol", "")
        self.host = entry.get("host")
        self.port = entry.get("port")
        self.address_string = entry.get("address")

    @property
    def address(self):
        """``(host, port)``, or ``None`` for a server with no listening socket."""
        if self.host is None or self.port is None:
            return None
        return (self.host, self.port)

    def __repr__(self):
        return f"Server(id={self.id}, protocol={self.protocol!r}, address={self.address_string!r})"


class Client:
    """One client from the readiness report."""

    def __init__(self, entry):
        self.id = entry.get("id")
        self.protocol = entry.get("protocol", "")
        self.remote_addr = entry.get("remote_addr", "")
        self.status = entry.get("status", "")

    def __repr__(self):
        return f"Client(id={self.id}, protocol={self.protocol!r}, status={self.status!r})"


class NetGet:
    """A NetGet process started for a test.

    :param config: path to a ``.netget`` file (relative paths are resolved against the
        current directory).
    :param actions: a list of actions, or a whole ``{"actions": [...]}`` document. Exactly one
        of ``config`` and ``actions`` may be given; with neither, ``args`` must say what to run.
    :param binary: the ``netget`` executable.
    :param args: extra command-line arguments.
    :param no_model: point the model at a closed port (see ``CLOSED_MODEL_URL``).
    :param ready_timeout: seconds to wait for the readiness report.
    :param max_lifetime: seconds after which NetGet stops itself (``--run-for``) even if the
        test never does -- a backstop for a test process that is killed outright.
    """

    def __init__(
        self,
        config=None,
        actions=None,
        binary=None,
        args=(),
        no_model=False,
        ready_timeout=30.0,
        max_lifetime=None,
    ):
        if config is not None and actions is not None:
            raise ValueError("give config or actions, not both")
        self._config = os.path.abspath(config) if config is not None else None
        self._actions = actions
        self._binary = binary or os.environ.get("NETGET_BIN") or "netget"
        self._args = list(args)
        self._no_model = no_model
        self._ready_timeout = ready_timeout
        self._max_lifetime = max_lifetime
        self._process = None
        self._dir = None
        self.servers = []
        self.clients = []
        self.report = None

    # -- lifecycle ---------------------------------------------------------------------------

    def start(self):
        """Start NetGet and block until it reports ready. Returns ``self``."""
        if self._process is not None:
            raise RuntimeError("already started")
        self._dir = tempfile.mkdtemp(prefix="netget-fixture-")
        try:
            self._spawn()
            self._wait_ready()
        except BaseException:
            self.stop()
            raise
        return self

    def stop(self):
        """Stop NetGet (if running) and remove its working directory."""
        process, self._process = self._process, None
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        if self._dir is not None:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False

    # -- what started ------------------------------------------------------------------------

    def server(self, protocol):
        """The first server of ``protocol`` (case-insensitive), or ``None``."""
        wanted = protocol.lower()
        for server in self.servers:
            if server.protocol.lower() == wanted:
                return server
        return None

    def address(self, protocol):
        """``(host, port)`` of the first server of ``protocol``. Raises ``LookupError``."""
        server = self.server(protocol)
        if server is None:
            started = [s.protocol for s in self.servers]
            raise LookupError(f"no {protocol} server; started: {started}")
        if server.address is None:
            raise LookupError(f"the {protocol} server has no listening socket")
        return server.address

    def url(self, protocol="http", scheme="http"):
        """``scheme://host:port`` for the first server of ``protocol``."""
        host, port = self.address(protocol)
        if ":" in host:
            host = f"[{host}]"
        return f"{scheme}://{host}:{port}"

    @property
    def pid(self):
        return self._process.pid if self._process is not None else None

    @property
    def work_dir(self):
        """NetGet's working directory: ``netget.log``, ``stdout.log``, ``stderr.log``."""
        return self._dir

    def stdout(self):
        """Everything NetGet has printed to stdout so far."""
        return self._read("stdout.log")

    def stderr(self):
        """Everything NetGet has printed to stderr so far."""
        return self._read("stderr.log")

    def log(self):
        """The contents of ``netget.log`` so far."""
        return self._read("netget.log")

    # -- internals ---------------------------------------------------------------------------

    def _read(self, name):
        if self._dir is None:
            return ""
        try:
            with open(os.path.join(self._dir, name), "rb") as handle:
                return handle.read().decode("utf-8", "replace")
        except FileNotFoundError:
            return ""

    def _spawn(self):
        command = [self._binary]
        if self._config is not None:
            command += ["--load", self._config]
        elif self._actions is not None:
            document = self._actions
            if isinstance(document, list):
                document = {"actions": document}
            path = os.path.join(self._dir, "fixture.netget")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            command += ["--load", path]
        self._ready_file = os.path.join(self._dir, "ready.json")
        command += ["--ready-file", self._ready_file]
        if self._no_model:
            command += ["--ollama-url", CLOSED_MODEL_URL]
        if self._max_lifetime is not None:
            command += ["--run-for", str(max(1, int(self._max_lifetime)))]
        command += self._args
        stdout = open(os.path.join(self._dir, "stdout.log"), "wb")
        stderr = open(os.path.join(self._dir, "stderr.log"), "wb")
        try:
            # NetGet writes netget.log into its working directory.
            self._process = subprocess.Popen(
                command,
                cwd=self._dir,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
            )
        except OSError as error:
            raise NetGetError(f"could not run {self._binary}: {error}") from error
        finally:
            stdout.close()
            stderr.close()

    def _wait_ready(self):
        deadline = time.monotonic() + self._ready_timeout
        while True:
            # Renamed into place complete, so existing means readable in full.
            try:
                with open(self._ready_file, encoding="utf-8") as handle:
                    report = json.load(handle)
                break
            except FileNotFoundError:
                pass
            status = self._process.poll()
            if status is not None:
                raise NetGetError(
                    f"netget exited with status {status} before it was ready", self.stderr()
                )
            if time.monotonic() >= deadline:
                raise NetGetError(
                    f"netget was not ready within {self._ready_timeout}s", self.stderr()
                )
            time.sleep(0.02)
        self.report = report
        self.servers = [Server(entry) for entry in report.get("servers", [])]
        self.clients = [Client(entry) for entry in report.get("clients", [])]
