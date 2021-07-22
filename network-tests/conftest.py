
import pytest
import pyoxenmq
import json
import random

def pytest_addoption(parser):
    parser.addoption("--exclude", action="store", default="")


@pytest.fixture(scope="module")
def omq():
    omq = pyoxenmq.OxenMQ()
    omq.start()
    return omq


@pytest.fixture(scope="module")
def mns(omq):
    remote = omq.connect_remote("curve://public.beldex.io:38161/80adaead94db3b0402a6057869bdbe63204a28e93589fd95a035480ed6c03b45")
    x = omq.request(remote, "rpc.get_master_nodes")
    assert(len(x) == 2 and x[0] == b'200')
    return json.loads(x[1])


@pytest.fixture(scope="module")
def random_mn(omq, mns):
    mn = random.choice(mns['master_node_states'])
    addr = "curve://{}:{}/{}".format(mn['public_ip'], mn['storage_lmq_port'], mn['pubkey_x25519'])
    conn = omq.connect_remote(addr)
    return conn


@pytest.fixture
def sk():
    from nacl.signing import SigningKey
    return SigningKey.generate()


@pytest.fixture
def exclude(pytestconfig):
    s = pytestconfig.getoption("exclude")
    return {s} if s and len(s) else {}
