"""pytest plugin: a ``netget`` fixture that starts NetGet and stops it after the test.

Enable with ``-p netget_fixture.pytest_plugin`` on the command line, or in the root
``conftest.py``::

    pytest_plugins = ["netget_fixture.pytest_plugin"]

Then::

    def test_client_against_mock(netget):
        mock = netget(config="tests/api.netget", no_model=True)
        response = urllib.request.urlopen(mock.url("http") + "/users/7")

``netget(...)`` takes the same arguments as ``netget_fixture.NetGet`` and may be called more
than once per test; every instance is stopped at teardown. For a module- or session-wide
mock, write your own fixture around ``NetGet`` as a context manager.
"""

import pytest

from . import NetGet


@pytest.fixture
def netget():
    started = []

    def start(**kwargs):
        instance = NetGet(**kwargs).start()
        started.append(instance)
        return instance

    yield start
    for instance in reversed(started):
        instance.stop()
