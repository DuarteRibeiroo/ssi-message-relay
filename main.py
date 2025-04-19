import sys

from server.msg_server import run_server
from timestamp_server.timestamp_server import run_server as run_timestamp_server
from client.msg_client import run_client

if __name__ == '__main__':
    match sys.argv[1]:
        case "msg_server":
            run_server()
        case "timestamp_server":
            run_timestamp_server()
        case "client":
            run_client(sys.argv[2:])
        case _:
            sys.stderr.write("Invalid argument!\n")
            exit(1)
    