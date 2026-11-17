"""Shared fixtures for the aegis transport test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests.local_pki import PKI

sys.path.append(str(Path(__file__).parent.parent))


pytestmark = pytest.mark.asyncio



endpoints = {
    "node-1": {"port": 5555, "host": "127.0.0.1"},
    "node-2": {"port": 5554, "host": "127.0.0.1"},
    "node-3": {"port": 5553, "host": "127.0.0.1"},
    "gateway": {"port": 5552, "host": "127.0.0.1"},
}


@pytest.fixture
def pki(tmp_path):
    return PKI(tmp_path, endpoints, "aegis-test")


@pytest.fixture
def server_node(pki):
    return pki.make_node("node-1")


@pytest.fixture
def client_node(pki):
    return pki.make_node("node-2")


@pytest.fixture
def gateway_node(pki):
    return pki.make_node("gateway")


@pytest.fixture
def node3(pki):
    return pki.make_node("node-3")
