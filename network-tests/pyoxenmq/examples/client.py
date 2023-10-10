import pyoxenmq

def do_connected(mq, conn):
    print("connected via", conn)
    return mq.request(conn, "llarp.auth", ["dq3j4dj99w6wi4t4yjnya8sxtqr1rojt8jgnn6467o6aoenm3o3o.loki", "5:token"])

def do_request(mq):
    print('connect')
    conn = mq.connect_remote("ipc:///tmp/lmq.sock")
    if conn:
        return do_connected(lmq, conn)

def main():
    mq = pyoxenmq.OxenMQ()
    print("start")
    mq.start()
    print(do_request(mq))
    print("done")

if __name__ == '__main__':
    main()
