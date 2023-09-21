import pyoxenmq
import ss
import time
import base64
import json
from nacl.encoding import HexEncoder, Base64Encoder
from nacl.hash import blake2b
from nacl.signing import VerifyKey

def test_store(omq, random_mn, sk, exclude):
    swarm = ss.get_swarm(omq, random_mn, sk)

    mn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote("curve://{}:{}/{}".format(mn['ip'], mn['port_omq'], mn['pubkey_x25519']))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store a message for myself
    s = json.loads(omq.request(conn, 'storage.store', [json.dumps({
        "pubkey": 'bd' + sk.verify_key.encode().hex(),
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode("abc 123".encode()).decode()}).encode()])[0])

    hash = blake2b("{}{}".format(ts, exp).encode() + b'\x05' + sk.verify_key.encode() + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')

    assert len(s["swarm"]) == len(swarm['mnodes'])
    edkeys = {x['pubkey_ed25519'] for x in swarm['mnodes']}
    for k, v in s['swarm'].items():
        assert k in edkeys
        assert hash == v['hash']

        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(v['hash'].encode(), base64.b64decode(v['signature']))

    # NB: assumes the test machine is reasonably time synced
    assert(ts - 30000 <= s['t'] <= ts + 30000)


def test_store_retrieve_unauthenticated(omq, random_mn, sk, exclude):
    """Retrieves messages without authentication.  This test will break in the future when we turn
    on required retrieval signatures"""
    mns = ss.random_swarm_members(ss.get_swarm(omq, random_mn, sk), 2, exclude)
    conn1 = omq.connect_remote("curve://{}:{}/{}".format(mns[0]['ip'], mns[0]['port_omq'], mns[0]['pubkey_x25519']))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store a message for myself
    s = json.loads(omq.request(conn1, 'storage.store', [json.dumps({
        "pubkey": 'bd' + sk.verify_key.encode().hex(),
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode(b"abc 123").decode()}).encode()])[0])

    hash = blake2b("{}{}".format(ts, exp).encode() + b'\x05' + sk.verify_key.encode() + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')

    assert all(v['hash'] == hash for v in s['swarm'].values())

    conn2 = omq.connect_remote("curve://{}:{}/{}".format(mns[1]['ip'], mns[1]['port_omq'], mns[1]['pubkey_x25519']))
    r = json.loads(omq.request(conn2, 'storage.retrieve', [json.dumps({
        "pubkey": 'bd' + sk.verify_key.encode().hex() }).encode()])[0])

    assert len(r['messages']) == 1
    msg = r['messages'][0]
    assert msg['data'] == base64.b64encode(b'abc 123').decode()
    assert msg['timestamp'] == ts
    assert msg['expiration'] == exp
    assert msg['hash'] == hash


def test_store_retrieve_authenticated(omq, random_mn, sk, exclude):
    xsk = sk.to_curve25519_private_key()
    xpk = xsk.public_key
    mn_x = ss.random_swarm_members(ss.get_swarm(omq, random_mn, xsk), 1, exclude)[0]
    mn_ed = ss.random_swarm_members(ss.get_swarm(omq, random_mn, sk), 1, exclude)[0]
    conn_x = omq.connect_remote("curve://{}:{}/{}".format(mn_x['ip'], mn_x['port_omq'], mn_x['pubkey_x25519']))
    conn_ed = omq.connect_remote("curve://{}:{}/{}".format(mn_ed['ip'], mn_ed['port_omq'], mn_ed['pubkey_x25519']))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store message for myself, using both my ed25519 key and x25519 key to test different auth
    # modes
    s1 = json.loads(omq.request(conn_x, 'storage.store', [json.dumps({
        "pubkey": 'bd' + xpk.encode().hex(),
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode(b"abc 123").decode()}).encode()])[0])

    hash1 = blake2b("{}{}".format(ts, exp).encode() + b'\x05' + xpk.encode() + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')

    assert all(v['hash'] == hash1 for v in s1['swarm'].values())

    s2 = json.loads(omq.request(conn_ed, 'storage.store', [json.dumps({
        "pubkey": '03' + sk.verify_key.encode().hex(),
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode(b"def 456").decode()}).encode()])[0])

    hash2 = blake2b("{}{}".format(ts, exp).encode() + b'\x03' + sk.verify_key.encode() + b'def 456',
            encoder=Base64Encoder).decode().rstrip('=')

    to_sign = "retrieve{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    badsig = sig[0:4] + ('z' if sig[4] != 'z' else 'a') + sig[5:]

    r_good1 = json.loads(omq.request(conn_x, 'storage.retrieve', [
        json.dumps({
            "pubkey": 'bd' + xpk.encode().hex(),
            "timestamp": ts,
            "signature": sig,
            "pubkey_ed25519": sk.verify_key.encode().hex()
        }).encode()])[0])
    r_good2 = json.loads(omq.request(conn_ed, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "timestamp": ts,
            "signature": sig
        }).encode()])[0])
    r_bad1 = omq.request(conn_x, 'storage.retrieve', [
        json.dumps({
            "pubkey": 'bd' + xpk.encode().hex(),
            "timestamp": ts,
            "signature": badsig,  # invalid sig
            "pubkey_ed25519": sk.verify_key.encode().hex()
        }).encode()])
    r_bad2 = omq.request(conn_ed, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "timestamp": ts,
            "signature": badsig  # invalid sig
        }).encode()])
    r_bad3 = omq.request(conn_ed, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "timestamp": ts,
            #"signature": badsig  # has timestamp but missing sig
        }).encode()])

    assert len(r_good1['messages']) == 1
    msg = r_good1['messages'][0]
    assert msg['data'] == base64.b64encode(b'abc 123').decode()
    assert msg['timestamp'] == ts
    assert msg['expiration'] == exp
    assert msg['hash'] == hash1

    assert len(r_good2['messages']) == 1
    msg = r_good2['messages'][0]
    assert msg['data'] == base64.b64encode(b'def 456').decode()
    assert msg['timestamp'] == ts
    assert msg['expiration'] == exp
    assert msg['hash'] == hash2

    assert r_bad1 == [b'401', b'retrieve signature verification failed']
    assert r_bad2 == [b'401', b'retrieve signature verification failed']
    assert r_bad3 == [b'400', b"invalid request: Required field 'signature' missing"]


def exactly_one(iterable):
    found_one = any(iterable)
    found_more = any(iterable)
    return found_one and not found_more


def test_store_retrieve_multiple(omq, random_mn, sk, exclude):
    mns = ss.random_swarm_members(ss.get_swarm(omq, random_mn, sk), 2, exclude)
    conn1 = omq.connect_remote("curve://{}:{}/{}".format(mns[0]['ip'], mns[0]['port_omq'], mns[0]['pubkey_x25519']))


    basemsg = b"This is my message \x00<--that's a null, this is invalid utf8: \x80\xff"

    # Store 5 messages
    msgs = ss.store_n(omq, conn1, sk, basemsg, 5)

    # Retrieve all messages from the swarm (should give back the 5 we just stored):
    conn2 = omq.connect_remote("curve://{}:{}/{}".format(mns[1]['ip'], mns[1]['port_omq'], mns[1]['pubkey_x25519']))
    resp = omq.request(conn2, 'storage.retrieve', [json.dumps({
        "pubkey": 'bd' + sk.verify_key.encode().hex() }).encode()])

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert len(r['messages']) == 5
    for m in r['messages']:
        data = base64.b64decode(m['data'])
        source = next(x for x in msgs if x['hash'] == m['hash'])
        assert source['data'] == data
        assert source['req']['timestamp'] == m['timestamp']
        assert source['req']['expiry'] == m['expiration']

    # Store 6 more messages
    basemsg = b'another msg'
    new_msgs = ss.store_n(omq, conn2, sk, basemsg, 6, 1)

    # Retrieve using a last_hash so that we should get back only the 6:
    resp = omq.request(conn1, 'storage.retrieve', [json.dumps({
        "pubkey": 'bd' + sk.verify_key.encode().hex(),
        "last_hash": msgs[4]['hash']
        }).encode()])

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert len(r['messages']) == 6
    for m in r['messages']:
        data = base64.b64decode(m['data'])
        source = next(x for x in new_msgs if x['hash'] == m['hash'])
        assert source['data'] == data
        assert source['req']['timestamp'] == m['timestamp']
        assert source['req']['expiry'] == m['expiration']

    # Give an unknown hash which should retrieve all:
    r = json.loads(omq.request(conn2, 'storage.retrieve', [json.dumps({
        "pubkey": 'bd' + sk.verify_key.encode().hex(),
        "last_hash": "abcdef"
        }).encode()])[0])

