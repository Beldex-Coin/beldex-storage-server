import pyoxenmq
import time

def handle_auth(args):
    print(args)
    raise Exception("boobs")
    return "OK"

def main():
    lmq = pyoxenmq.OxenMQ()
    lmq.listen_plain("ipc:///tmp/lmq.sock")
    lmq.add_anonymous_category("llarp")
    lmq.add_request_command("llarp", "auth", handle_auth)
    lmq.start()
    print("server started")
    while True:
        time.sleep(1)

if __name__ == '__main__':
    main()
