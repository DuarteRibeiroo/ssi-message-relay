import os 
import bson
import sys
import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

from timestamp_server.load_certificate import SERVER_PRIVATE_KEY,SERVER_CERTIFICATE,CA_CERTIFICATE
from common.timestamp_server_msgs import *
from common.commonFunc import *
from common.validateCert import validate_cert

   
max_msg_size = 9999

class TimestampServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, reader, writer, addr=None):
        """ Construtor da classe. """
        self.id = cnt ## só usado para debug
        self.addr = addr
        self.reader = reader
        self.writer = writer
        self.client_id = None
        self.logfile = None # close when?????????????????????????????
        self.key = b""
        self.aesgcm = None

    # processar mensagem de cliente e enviar resposta
    async def answer(self):

        message = await self.read_from_server()
        #parse response to client
        server_msg_to_send = await self.parse_query(message)
    
        # for client in server.clients:

        #     print(f"CLIENT:\n{client}")

        await self.send_to_client(server_msg_to_send)

    # decrypts message with key from handshake
    async def read_from_server(self):
        enc_msg = await self.reader.read(max_msg_size) # encrypted client message
        #decrpyt message from client
        message = self.aesgcm.decrypt(enc_msg[:12],enc_msg[12:],None)

        return message
    
    # encrypts message with key from handshake
    async def send_to_client(self,msg_to_send):
        #encrypt message to client
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, msg_to_send, None)

        enc_msg = nonce + ct

        self.writer.write(enc_msg)
        await self.writer.drain()
        

## funcs de parse
    async def parse_timestamp_request(self,msg_data):
        #Get hash
        msg_hash = msg_data["hash"]
        #get timestamp
        timestamp = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
        #Sign hash + timestamp
        signature = SERVER_PRIVATE_KEY.sign(
            msg_hash + timestamp.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signed message with hash " + str(msg_hash) + " on " + timestamp)
        #Send timestamp + signature to message server
        return Timestamping_Msg.reply_timestamp_msg(timestamp.encode(),signature)

    async def parse_query(self,client_msg):
        decoded_msg = bson.loads(client_msg)
        print(decoded_msg)
        msg_data = decoded_msg["data"]
        match int(decoded_msg["id"]):
            # Timestamp a message
            case 0:
                msg_to_send = await self.parse_timestamp_request(msg_data)
            # Messages that are sent from this server, not received!
            case 1 | 2:
                sys.stderr.write("This query id should only be sent, not received!\n")
                exit(1)
            case _:
                sys.stderr.write("Query id unrecognized\n")
                exit(1)
        return bson.dumps(msg_to_send.__dict__)

    async def setup_shared_key(self):

        '''
        Protocol is as follows:
        1. Client generates secret and sends server public part of secret
        2. Server generates its own secret, sends it to client along with signing the two public secrets with the certificate's private key and its certificate
        3. Client sends to server signed public secrets and its certificate
        4. Both the client and server (after certificate verification) are sure they are talking to each other and have a shared secret with which they can encrypt messages messages
        '''

        #Read serialized client public secret and convert back to a key
        client_public_secret_bytes = await self.reader.read(max_msg_size)
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

        
        
        # print("Read keys from keystore")

        #Sign public secrets with certificate private key
        #Adapted from https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing´
        generated_secrets = server_public_secret_bytes + client_public_secret_bytes
        server_signature = SERVER_PRIVATE_KEY.sign(
            generated_secrets,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )   

        #Encode fields in pairs to parse easily
        signature_and_cert = mkpair(server_signature,SERVER_CERTIFICATE.public_bytes(serialization.Encoding.PEM))
        message = mkpair(server_public_secret_bytes,signature_and_cert)
        #Send message to client with server public secret, signature and certificate
        self.writer.write(message)

        #Read client public secrets signature and certificate
        client_message = await self.reader.read(max_msg_size)
        client_signature,client_certificate_bytes = unpair(client_message)
        client_certificate = x509.load_pem_x509_certificate(client_certificate_bytes)
        
        #Validate certificate and derive its key
        validate_cert(CA_CERTIFICATE, client_certificate)
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

