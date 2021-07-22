import pyoxenmq
import ss
import time
import base64
import json
from nacl.encoding import HexEncoder, Base64Encoder
from nacl.hash import blake2b
from nacl.signing import VerifyKey, SigningKey
from nacl.public import PrivateKey
import nacl.exceptions

def test_session_auth(omq, random_mn, sk, exclude):
    """
    Session key handling is a bit convoluted because it follows Signal's messy approach of exposing
    the more specific x25519 pubkey rather than the more general ed25519 pubkey; this test's SS's
    ability to handle this messy key situation.
    """

    xsk = sk.to_curve25519_private_key()
    xpk = xsk.public_key

    swarm = ss.get_swarm(omq, random_mn, xsk)
    mn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote("curve://{}:{}/{}".format(mn['ip'], mn['port_omq'], mn['pubkey_x25519']))

    msgs = ss.store_n(omq, conn, xsk, b"omg123", 5)

    my_ss_id = '05' + xsk.public_key.encode().hex()

    ts = int(time.time() * 1000)
    to_sign = "delete_all{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = {
            "pubkey": my_ss_id,
            "timestamp": ts,
            "signature": sig
    }

    resp = omq.request(conn, 'storage.delete_all', [json.dumps(params).encode()])

    # Expect this to fail because we didn't pass the Ed25519 key
    assert resp == [b'401', b'delete_all signature verification failed']

    # Make sure nothing was actually deleted:
    r = json.loads(omq.request(conn, 'storage.retrieve',
        [json.dumps({ "pubkey": my_ss_id }).encode()]
        )[0])
    assert len(r['messages']) == 5

    # Try signing with some *other* ed25519 key, which should be detected as not corresponding to
    # the x25519 pubkey and thus still fail
    fake_sk = SigningKey.generate()
    fake_sig = fake_sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params['pubkey_ed25519'] = fake_sk.verify_key.encode().hex()
    params['signature'] = fake_sig
    resp = omq.request(conn, 'storage.delete_all', [json.dumps(params).encode()])

    assert resp == [b'401', b'delete_all signature verification failed']

    # Make sure nothing was actually deleted:
    r = json.loads(omq.request(conn, 'storage.retrieve',
        [json.dumps({ "pubkey": my_ss_id }).encode()]
        )[0])
    assert len(r['messages']) == 5

    # Now send along the correct ed pubkey to make it work
    params['pubkey_ed25519'] = sk.verify_key.encode().hex()
    params['signature'] = sig
    resp = omq.request(conn, 'storage.delete_all', [json.dumps(params).encode()])

    assert len(resp) == 1
    r = json.loads(resp[0])

    # Make sure SS is using the correct pubkey for the signatures (i.e. the session x25519 key)
    msg_hashes = sorted(m['hash'] for m in msgs)
    expected_signed = "".join((my_ss_id, str(ts), *msg_hashes)).encode()
    for k, v in r['swarm'].items():
        assert v['deleted'] == msg_hashes
        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(expected_signed, base64.b64decode(v['signature']))


    # Verify deletion
    r = json.loads(omq.request(conn, 'storage.retrieve',
        [json.dumps({ "pubkey": my_ss_id }).encode()]
        )[0])
    assert not r['messages']


def test_non_session_no_ed25519(omq, random_mn, sk, exclude):
    """
    Test that the session key hack doesn't work for non-Session addresses (i.e. when not using the
    05 prefix).
    """

    xsk = sk.to_curve25519_private_key()
    xpk = xsk.public_key

    swarm = ss.get_swarm(omq, random_mn, xsk, netid=4)
    mn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote("curve://{}:{}/{}".format(mn['ip'], mn['port_omq'], mn['pubkey_x25519']))

    msgs = ss.store_n(omq, conn, xsk, b"omg123", 4)

    my_ss_id = '04' + xsk.public_key.encode().hex()

    ts = int(time.time() * 1000)
    to_sign = "delete_all{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = {
            "pubkey": my_ss_id,
            "pubkey_ed25519": sk.verify_key.encode().hex(),
            "timestamp": ts,
            "signature": sig
    }

    resp = omq.request(conn, 'storage.delete_all', [json.dumps(params).encode()])

    assert resp == [b'400', b'invalid request: pubkey_ed25519 is only permitted for 05[...] pubkeys']
