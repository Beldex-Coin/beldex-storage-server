import pyoxenmq
import time

def handle_ping(args):
    print(args)
    return args

lmq = pyoxenmq.OxenMQ()
lmq.listen_plain("ipc:///tmp/lmq.sock")
lmq.add_anonymous_category("python")
lmq.add_request_command("python", "ping", handle_ping)
lmq.start()

while True:
    time.sleep(1)
