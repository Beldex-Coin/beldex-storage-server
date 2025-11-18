from oxenmq import Address
import random


def mn_address(mn):
    return Address(mn['ip'], mn['port_omq'], bytes.fromhex(mn['pubkey_x25519']))

def random_time_delta_ms(upper: int) -> int:
    return random.randint(1, upper * 1000)