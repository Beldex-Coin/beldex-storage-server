import pyoxenmq
import base64
import subprocess
import shlex
import argparse
import io
import time
import traceback

def decode_str(data, first=None):
    l = b''
    if first is not None:
        l += first
    while True:
        ch = data.read(1)
        if ch == b':':
            return data.read(int(l.decode('ascii')))
        else:
            l += ch

def decode_list(data, first=None):
    l = []
    while True:
        ch = data.read(1)
        if ch == b'e':
            return l
        l += decode_value(data, first=ch)

def decode_dict(data, first=None):
    d = dict()
    while True:
        ch = data.read(1)
        if ch == b'e':
            return d
        k = decode_str(data, first=ch)
        v = decode_value(data)
        d[k] = v

def decode_int(data, first=None):
    i = b''
    while True:
        ch = data.read(1)
        if ch == b'e':
            return int(i.decode('ascii'))
        i += ch

def decode_value(data, first=None):
    if first:
        ch = first
    else:
        ch = data.read(1)
    if ch in b'0123456789':
        return decode_str(data, first=ch)
    if ch == b'i':
        return decode_int(data, first=ch)
    if ch == b'd':
        return decode_dict(data, first=ch)
    if ch == b'l':
        return decode_list(data, first=ch)
    raise Exception("invalid char: {}".format(ch))


def decode_address(data):
    return '{}.beldex'.format(pyoxenmq.base32z_encode(decode_value(data)[b's'][b's']))

def handle_auth_impl(args, cmd):
    cmd2 = cmd
    cmd2.append(decode_address(io.BytesIO(args[0])))
    cmd2.append(base64.b64encode(args[1]).decode('ascii'))
    result = subprocess.run(args=cmd2, check=False)
    if result.returncode == 0:
        return "OKAY"
    else:
        return "REJECT"
    
def handle_auth(args, cmd):
    try:
        return handle_auth_impl(args, cmd)
    except:
        traceback.print_exc()
    
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True, help="url to bind auth socket to")
    ap.add_argument("--cmd", required=True, help="script to call for authentication")
    args = ap.parse_args()
    cmd = shlex.split(args.cmd)
    mq = pyoxenmq.OxenMQ()
    mq.listen_plain(args.bind)
    mq.add_anonymous_category("llarp")
    mq.add_request_command("llarp", "auth", lambda x : handle_auth(x, cmd))
    mq.start()
    print("server started")
    while True:
        time.sleep(1)

if __name__ == '__main__':
    main()

