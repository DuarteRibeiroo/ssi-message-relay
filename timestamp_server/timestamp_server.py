#!/usr/bin/env python3

# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import datetime

from timestamp_server.timestamp_server_worker import *


conn_cnt = 0
conn_port = 8444
max_msg_size = 9999

async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = TimestampServerWorker(conn_cnt, reader, writer, addr=addr) # arranjar melhor maneira de associar o reader e writer a serverworker??

    #setup shared key
    await srvwrk.setup_shared_key()

    print("Finished initial handshake")

    await srvwrk.answer()

    print("Closed serverWorker [%d]" % srvwrk.id)
    writer.close()

def run_server():
    
    loop = asyncio.new_event_loop()
    coro = asyncio.start_server(lambda r, w: handle_echo(r,w), '127.0.0.1', conn_port) # maneira manhosa que descobri para passar argumentos adicionais à corotina handle_echo
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

if __name__ == '__main__':
    run_server()

