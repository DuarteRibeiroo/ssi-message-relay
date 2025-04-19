#!/usr/bin/env python3

# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import os 

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common.client_handshake_shared_key import *


timestamp_server_port = 8444
max_msg_size = 9999

class Timestamping_Server_Socket:
    """ Classe que implementa envio e receção de mensagens pela socket, e encriptação AESGCM das mensagens na socket. """
    def __init__(self, host, port=timestamp_server_port):
        """ Construtor da classe. """
        self.host = host
        self.port = port
        self.key = b""
        self.aesgcm = None
        self.addr = None
        self.reader = None
        self.writer = None
        
    async def setup_shared_key(self, keystore_path):
        result = await setup_shared_key(self.reader,self.writer,keystore_path)
        if (result is not None):
            (client_cert_private_key,shared_key) = result
            self.set_shared_key(shared_key)
            # print("Finished initial handshake")
        else:
            print("Error handshaking secret_key")
            exit(1)

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.addr = self.writer.get_extra_info('peername')

    """ Devolve resposta do servidor, desencripta com AESGCM"""
    async def read_from_server(self):
        server_response = None
        server_response_enc_msg = await self.reader.read(max_msg_size)
        if server_response_enc_msg :
            server_response = self.aesgcm.decrypt(server_response_enc_msg[:12],server_response_enc_msg[12:],None)
        return server_response
    
    """ Envia mensagem recebida em bytes para servidor, encripta com AESGCM"""
    async def send_to_server(self, msg=""):
        if (msg):
            nonce = os.urandom(12)
            ct = self.aesgcm.encrypt(nonce, msg, None)
            client_enc_msg = nonce + ct
            self.writer.write(client_enc_msg)
            await self.writer.drain()

    def set_shared_key(self, shared_key):
        self.key = shared_key
        self.aesgcm = AESGCM(self.key)

    def close_connection(self):
        self.writer.write(b'\n')
        # print('Socket closed!')
        self.writer.close()