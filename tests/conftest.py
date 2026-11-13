"""Shared fixtures for the aegis transport test suite."""
from __future__ import annotations



import pytest
import sys 
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))


from libs.transport.tls import TlsConnection

pytestmark = pytest.mark.asyncio



from local_pki import PKI



@pytest.fixture
def pki(tmp_path):
    return PKI(tmp_path, ["node-1", "node-2"], "aegis-test")


@pytest.fixture
def server_node(pki):
    return pki.make_node("node-1", "127.0.0.1", 0)


@pytest.fixture
def client_node(pki):
    return pki.make_node("node-2", "127.0.0.1", 0)

