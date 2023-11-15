from oxenmq import Address

def mn_address(mn):
    return Address(mn['ip'], mn['port_omq'], bytes.fromhex(mn['pubkey_x25519']))
