#!/usr/bin/env python3

import asyncio
from client.client_class import *

conn_port = 8443

async def main_loop(args):
    clientSocket = Client_Socket('127.0.0.1', conn_port)
    client = Client(clientSocket)
    await client.connect()
    # print("Started connection")

    # parse if -user flag is used to change client_keystore_path 
    input_args, keystore_path = parse_input_keystore_path(args)

    await client.setup_shared_key(keystore_path)
    
    await client.answer_input(input_args)

    #close connection
    client.close_connection()

# processa se existe a flag de especificar ficheiro com dados do utilizador nos argumentos do programa
# devolve (posição onde começar a ler os argumentos para interpretar o resto do pedido do cliente, path_ficheiro_dados)
def parse_input_keystore_path(args):
    try :
        if "-user" in args:
            user_keystore_path = args[args.index("-user") + 1]
            # print("Changed keystore path to " + user_keystore_path)
            return (args[args.index("-user") + 2:],user_keystore_path)
        
        else:
            return (args,user_default_data_path)
    except Exception as e:
        sys.stderr.write("MSG RELAY SERVICE: command error!" + help_instructions() + "\n")
        exit(1)


def run_client(args):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main_loop(args))

if __name__ == '__main__':
    run_client(args=sys.argv)