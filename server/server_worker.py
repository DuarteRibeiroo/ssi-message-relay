import os 
import bson
import sys
import hashlib
import datetime


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509


from server.server_msgs import *
from server.timestamp_server_connection import *

from common.commonFunc import *
from common.validateCert import validate_cert
from common.timestamp_server_msgs import *

   
max_msg_size = 9999

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, server, reader, writer, addr=None):
        """ Construtor da classe. """
        self.id = cnt ## só usado para debug
        self.addr = addr
        self.reader = reader
        self.writer = writer
        self.client_id = None
        self.logfile = None # close when?????????????????????????????
        self.key = b""
        self.aesgcm = None
        self.server = server # instância de server, a partir da qual se acede a arrays comuns

    # processar mensagem de cliente e enviar resposta
    async def answer(self):

        message = await self.read_from_client()

        #parse response to client
        server_msg_to_send = await self.parse_query(message)
    
        await self.send_to_client(server_msg_to_send)

    # decrypts message with key from handshake
    async def read_from_client(self, afterHandshake = True):
        message_bytes = await self.reader.read(max_msg_size) # message from client

        if(afterHandshake):
            #decrypt message from client with aesgcm
            message_bytes = self.aesgcm.decrypt(message_bytes[:12],message_bytes[12:],None)

        message = bson.loads(message_bytes)
        return message
    
    # encrypts message with key from handshake
    async def send_to_client(self, msg_to_send, afterHandshake = True):
        #encrypt message to client
        msg_bytes = bson.dumps(msg_to_send)
        if (afterHandshake):
            #encrypt message with aesgcm
            nonce = os.urandom(12)
            ct = self.aesgcm.encrypt(nonce, msg_bytes, None)
            msg_bytes = nonce + ct

        self.writer.write(msg_bytes)
        await self.writer.drain()

## funcs de parse
    async def parse_send_message(self,msg_data):
        client = self.server.get_client(msg_data["dest_uid"])

        #se não houver o cliente
        if client is None:
            return Serv_To_Cli_Msg.reply_success_action(False,{"error": "Destination client isn't in the system"})
        
        #enviar certificado público de cliente destino, para cliente origem encriptar conteudo de msg com essa chave
        dest_client_CRT = client.certificate.public_bytes(serialization.Encoding.PEM)
        
        cert_msg = Serv_To_Cli_Msg.reply_success_action(True, {"certificate" : dest_client_CRT})

        await self.send_to_client(cert_msg.__dict__)


        client_response = await self.read_from_client()
        msg_data_body = client_response["msg_body"]
        
        #Ask timestamping server for signed timestamp
        timestamp_server = Timestamping_Server_Socket('127.0.0.1')
        await timestamp_server.connect()

        await timestamp_server.setup_shared_key('projCA/MSG_SERVER.p12')
        msg_body_hash = hashlib.sha256(msg_data_body).digest()
        await timestamp_server.send_to_server(bson.dumps(Timestamping_Msg.request_timestamp_msg(msg_body_hash).__dict__))
        timestamp_server_msg_bytes = await timestamp_server.read_from_server()
        timestamp_server_msg = bson.loads(timestamp_server_msg_bytes)
        timestamp_bytes = timestamp_server_msg["data"]["timestamp"]
        timestamp_str = timestamp_bytes.decode()
        timestamp_signature = timestamp_server_msg["data"]["signature"]
    
        client.add_msg(self.client_id, timestamp_bytes,timestamp_signature, msg_body_hash, msg_data["subject"], msg_data_body)


        self.log(f'Received send request\n    TO: {msg_data["dest_uid"]}    SUBJECT: {msg_data["subject"]}    TIMESTAMP: {timestamp_str} BODY_LEN: {len(msg_data_body)}\n')

        #alguma situação podia levar esta operação a falhar??
        return Serv_To_Cli_Msg.reply_success_action(True)

    def parse_ask_queue(self,msg_data):
        client = self.server.get_client(self.client_id)
        queue = client.get_unread_queue()
        
        if (queue == []):
            self.log(f'Received queue request. Queue is empty\n')
        else:
            res = "Received queue request. Response:\n"
            for msg in queue:
                res += f'    {msg.data["num"]}: TO: {msg.data["dest_uid"]}    SUBJECT: {msg.data["subject"]}    TIMESTAMP: {msg.data["timestamp"]} BODY_LEN: {len(msg.data["body"])}\n'
            self.log(res)

        return Serv_To_Cli_Msg.reply_ask_queue_msg(queue)

    def parse_get_msg(self,msg_data):
        dest_client = self.server.get_client(self.client_id)
        wanted_msg = dest_client.read_msg(msg_data["msg_num"])
        if (wanted_msg is not None):
            src_client = self.server.get_client(wanted_msg.data["src_uid"])

            src_client_CRT_bytes = src_client.certificate.public_bytes(serialization.Encoding.PEM)

            self.log(f'Received get request. Message {str(msg_data["msg_num"])} info:\nTO: {wanted_msg.data["dest_uid"]}    SUBJECT: {wanted_msg.data["subject"]}    TIMESTAMP: {wanted_msg.data["timestamp"]} BODY_LEN: {len(wanted_msg.data["body"])}\n')

            return Serv_To_Cli_Msg.reply_get_msg_msg(wanted_msg, src_client_CRT_bytes,wanted_msg.data["src_uid"])
    
        else:
            self.log(f'Received get request. Message {str(msg_data["msg_num"])} does not exist\n')
            return Serv_To_Cli_Msg.reply_success_action(False)

    async def parse_query(self,client_msg):
        decoded_msg = client_msg
        print(decoded_msg)
        msg_data = decoded_msg["data"]
        match decoded_msg["id"]:
            case 1:
                msg_to_send = await self.parse_send_message(msg_data)
            case 2:
                msg_to_send = self.parse_ask_queue(msg_data)
            case 3:
                msg_to_send = self.parse_get_msg(msg_data)
            case _:
                self.log(f'Invalid query ID: {str(decoded_msg["id"])}\n')
                sys.stderr.write("Query id unrecognized")
                exit(1)
        return msg_to_send.__dict__

    async def setup_shared_key(self):

        '''
        Protocol is as follows:
        1. Client generates secret and sends server public part of secret
        2. Server generates its own secret, sends it to client along with signing the two public secrets with the certificate's private key and its certificate
        3. Client sends to server signed public secrets and its certificate
        4. Both the client and server (after certificate verification) are sure they are talking to each other and have a shared secret with which they can encrypt messages messages
        '''

        #Read serialized client public secret and convert back to a key
        cli_answer = await self.read_from_client(False)

        client_public_secret_bytes = cli_answer["cli_pub_secret"]

        client_public_secret = serialization.load_pem_public_key(client_public_secret_bytes)

        #Predetermined parameters for secret generation
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2
        #Generate private secret
        parameters = dh.DHParameterNumbers(p,g).parameters()
        server_private_secret = parameters.generate_private_key()
        
        #Extract public part of secret from private secret and serialize it with PEM
        server_public_secret_bytes = server_private_secret.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        #Load server private key, certificate and ca certificate from pre-defined keystore file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        p12_file_path = 'projCA/MSG_SERVER.p12'

        key_cert_data = get_userdata(p12_file_path,None)
        if (key_cert_data is not None):
            server_private_key, server_certificate, ca_certificate = key_cert_data
        else:
            return None
        
        # print("Read keys from keystore")

        #Sign public secrets with certificate private key
        #Adapted from https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing´
        generated_secrets = server_public_secret_bytes + client_public_secret_bytes
        server_signature = server_private_key.sign(
            generated_secrets,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )   

        #Send message to client with server public secret, signature and certificate
        message = {"serv_pub_secret": server_public_secret_bytes, "serv_sign": server_signature, "serv_cert": server_certificate.public_bytes(serialization.Encoding.PEM)}
        await self.send_to_client(message, False)

        #Read client public secrets signature and certificate
        client_message = await self.read_from_client(False)

        client_signature,client_certificate_bytes = client_message["cli_sign"], client_message["cli_cert"]
        client_certificate = x509.load_pem_x509_certificate(client_certificate_bytes)
        
        #Validate certificate and derive its key
        validate_cert(ca_certificate, client_certificate)
        client_certificate_public_key = client_certificate.public_key()

        #Verify signature 
        client_certificate_public_key.verify(
            client_signature,
            client_public_secret_bytes + server_public_secret_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        #Generate shared secret
        shared_key = server_private_secret.exchange(client_public_secret)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            ).derive(shared_key)
        
        # print(f"Derived key: {derived_key}")
        #save shared key and start aesgcm with key
        self.key = derived_key
        self.aesgcm = AESGCM(self.key)

        #save client info in server
        for name in client_certificate.subject:
            if name.oid == x509.NameOID.PSEUDONYM:
                self.client_id = name.value
                self.server.add_client(name.value, client_certificate)
                break

        if self.client_id is None:
            raise x509.ExtensionNotFound("Pseudonym not found in client certificate")
        
        self.logfile = open("server/logs/" + str(self.client_id) + ".log", "a")
        self.log(f"Connection estabilished at {datetime.datetime.now(tz=datetime.timezone.utc)}\n")


    def log(self, info):
        # print("LOGGING")
        # print(info)
        self.logfile.write(info)
        self.logfile.flush()
