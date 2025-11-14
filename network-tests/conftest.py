
import pytest
from oxenmq import OxenMQ, Address
import json
import random

def pytest_addoption(parser):
    parser.addoption("--exclude", action="store", default="")


@pytest.fixture(scope="module")
def omq():
    omq = OxenMQ()
    omq.max_message_size = 10 * 1024 * 1024
    omq.start()
    return omq


@pytest.fixture(scope="module")
def bns(omq):
    remote = omq.connect_remote(
        Address(
            "curve://public.loki.foundation:38161/80adaead94db3b0402a6057869bdbe63204a28e93589fd95a035480ed6c03b45"
        )
    )
    x = omq.request_future(remote, "rpc.get_master_nodes", b'{"active_only": true}').get()
    assert len(x) == 2 and x[0] == b'200'
    return json.loads(x[1])


@pytest.fixture(scope="module")
def random_mn(omq, bns):
    mn = random.choice(bns['master_node_states'])
    addr = Address(mn['public_ip'], mn['storage_lmq_port'], bytes.fromhex(mn['pubkey_x25519']))
    conn = omq.connect_remote(addr)
    return conn


@pytest.fixture
def sk():
    from nacl.signing import SigningKey

    return SigningKey.generate()


@pytest.fixture(scope="module")
def exclude(pytestconfig):
    s = pytestconfig.getoption("exclude")
    return {s} if s and len(s) else {}
