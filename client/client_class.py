### Módulo em que se processa os pedidos e constrói-se os bytes da mensagem a enviar para o servidor

import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


from client.client_msgs import *
from client.client_socket import *
from common.client_handshake_shared_key import *
from common.validateCert import validate_cert

user_default_data_path = "projCA/userdata.p12"


### PARSE INPUTS #####
class Client():
    def __init__(self, clientSocket):
        self.socket = clientSocket
        self.cert_priv_key = None

    async def connect(self):
        await self.socket.connect()
    
        #setup shared key
    async def setup_shared_key(self, keystore_path):
        client_cert_priv_key = await self.socket.setup_shared_key(keystore_path)
        if (client_cert_priv_key is not None):
            self.cert_priv_key = client_cert_priv_key
            # print("Finished initial handshake")
        else:
            print("Error handshaking secret_key")
            exit(1)

    def close_connection(self):
        self.socket.close_connection()

    async def answer_input(self, input_args):

        #process rest of terminal input
        server_response = await self.parse_input_action(input_args)

        self.parse_output_action(server_response)

    async def send_message(self, uid, subject):
        try:
            msg_to_send = Cli_To_Serv_Msg.create_send_request_msg(uid,subject)
            msg_to_send_bytes =  msg_to_send.__dict__
            await self.socket.send_to_server(msg_to_send_bytes)

            server_response = await self.socket.read_from_server()

            #If server response is unsuccessfull, return immediately
            if server_response["id"] == "2":
                return server_response
            
            #Else proceed with sending body

            #Read client certificate sent from server
            dest_client_CRT = x509.load_pem_x509_certificate(server_response["data"]["certificate"])
            
            #Read CA certificate
            #Adapted from https://cryptography.io/en/latest/x509/reference/#x-509-certificate-validation
            with open("projCA/MSG_CA.crt", "rb") as ca_cert_file:
                ca_certificate = x509.load_pem_x509_certificate(ca_cert_file.read())
                
            # Validate certificte sent from server
            validate_cert(ca_certificate,dest_client_CRT,uid)
            #Get certificate public key
            dest_client_PK = dest_client_CRT.public_key()
            
            #Read user message
            print("Write message body:")
            user_input = sys.stdin.read()[:1000]

            # if (len(user_input) > 1000):
            #     print("Message is too long, it will be chopped to first 1000 characters")

            #assinar input com chave privada de utilizador, para garantir que veio dele
            client_signature = self.cert_priv_key.sign(
                user_input.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            input_with_signature = client_signature + user_input.encode()

            try:
                # Gerar random symmetric key
                symmetric_key = os.urandom(32) # 256-bit key for AES

                cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(b"\x00" * 16)) # mudar isto depois talvez??
                encryptor = cipher.encryptor()

                #encriptar conteúdo extenso com symmetric key
                enc_input_with_signature = encryptor.update(input_with_signature) + encryptor.finalize()

                #encriptar key simétrica (conteúdo pequeno) com chave pública
                enc_sym_key = dest_client_PK.encrypt(
                    symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                enc_data = {"msg_body": enc_sym_key + enc_input_with_signature}

            except Exception as e:
                print("Errror" + e)
            
            await self.socket.send_to_server(enc_data)

            server_response = await self.socket.read_from_server()

            return server_response
        
        except Exception as e:
            print(e)
            print(f"Error| Type: {type(e).__name__} Info:{e}")


    async def ask_queue(self):

        client_msg_to_send = Cli_To_Serv_Msg.create_ask_queue_msg()
        msg_to_send_bytes = client_msg_to_send.__dict__ # nota: __dict__ transforma objeto Cli_To_Serv_Msg diretamente em dicionário que pode ser serializado por bson!
        
        # send to server encrypted message and decrypt response
        await self.socket.send_to_server(msg_to_send_bytes)

        server_response = await self.socket.read_from_server()

        return server_response
    
    async def get_msg(self, msg_num):
        msg_to_send = Cli_To_Serv_Msg.create_get_msg_msg(msg_num)
        msg_to_send_bytes =  msg_to_send.__dict__
        await self.socket.send_to_server(msg_to_send_bytes)

        server_response = await self.socket.read_from_server()
        
        if server_response["id"] == "4":
            enc_body = server_response["data"]["msg"]["body"]
            #Read client certificate sent from 
            src_CRT_bytes = server_response["data"]["src_CRT"]
            src_client_CRT = x509.load_pem_x509_certificate(src_CRT_bytes)
            src_uid = server_response["data"]["src_uid"]
            
            #Read CA certificate
            #Adapted from https://cryptography.io/en/latest/x509/reference/#x-509-certificate-validation
            with open("projCA/MSG_CA.crt", "rb") as ca_cert_file:
                ca_certificate = x509.load_pem_x509_certificate(ca_cert_file.read())
                
            # Validate certificte sent from server
            validate_cert(ca_certificate,src_client_CRT,src_uid)
            #Get certificate public key
            src_PK = src_client_CRT.public_key()
            
            #Read timestamp authority certificate (MSG_TIMESTAMP)
            key_cert_data = get_userdata("projCA/MSG_TIMESTAMP.p12",None)

            if (key_cert_data is not None):
               timestamp_server_certificate = key_cert_data[1]
            else:
                return None
            
            timestamp_server_pub_key = timestamp_server_certificate.public_key()
            
            #Validate timestamp
            timestamp = server_response["data"]["msg"]["timestamp"]
            msg_hash = server_response["data"]["msg"]["body_hash"]
            timestamp_signature = server_response["data"]["msg"]["timestamp_sig"]
            timestamp_server_pub_key.verify(
                timestamp_signature,
                msg_hash + timestamp,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Timestamp verified!")

            #separar conteúdo em chave simétrica encriptada, conteúdo encriptado por chave simétrica
            (enc_sym_key, enc_input_with_signature) = enc_body[:256],enc_body[256:]

            #desencriptar chave simétrica com chave privada de destino
            dec_sym_key = self.cert_priv_key.decrypt(
                enc_sym_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            #desencriptar conteúdo da mensagem com chave simétrica
            cipher = Cipher(algorithms.AES(dec_sym_key), modes.CTR(b"\x00" * 16))
            decryptor = cipher.decryptor()
            dec_input_with_signature = decryptor.update(enc_input_with_signature) + decryptor.finalize()

            #separa assinatura e conteúdo desencriptado da mensagem
            msg_signature = dec_input_with_signature[:256]
            msg_decrypted_body = dec_input_with_signature[256:]

            try:
                src_PK.verify(
                    msg_signature,
                    msg_decrypted_body,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            
                
            except:
                sys.stderr.write("MSG RELAY SERVICE: verification error!\n")

            server_response["data"]["msg"]["body"] = msg_decrypted_body.decode()

        else:
            sys.stderr.write("MSG RELAY SERVICE: unknown message!\n")
            server_response = None

        return server_response
    
    #processa o resto dos argumentos do programa e cria mensagem a enviar ao servidor (em bytes)
    async def parse_input_action(self, args):
        # try :
            match args[0]:
                case "send":
                    result_msg = await self.send_message(args[1],args[2])
                case "askqueue":
                    result_msg = await self.ask_queue()
                case "getmsg":
                    result_msg = await self.get_msg(args[1])
                case "help":
                    print(self.help_instructions())
                    return b""
                case _:
                    raise Exception("Input unrecognized")

            return result_msg  
        # except Exception as e:
        #     sys.stderr.write("MSG RELAY SERVICE: command error!" + str(e) + help_instructions() + "\n")
        #     exit(1)

    ### PARSE OUTPUTS #####
        
    def reply_success(self, msg):
        print("MSG RELAY SERVICE: Action successful")
        if (msg != {}):
            print(msg)

    def reply_fail(self, msg):
        sys.stderr.write("MSG RELAY SERVICE: Action unsuccessful\n")
        if (msg != {}):
            sys.stderr.write(msg["error"] + "\n")

    def reply_ask_queue(self, msg):
        if msg["queue"] == '':
            print("MSG RELAY SERVICE: Queue\nEmpty...")
        else:
            print("MSG RELAY SERVICE: Queue")
            print(msg["queue"])

    def reply_get_msg(self, msg_data):
        output = "MSG RELAY SERVICE: Message:\n"
        msg = msg_data["msg"]
        output += f'Num: {msg["num"]}\n'
        output += f'From: {msg["src_uid"]}\n'
        output += f'To: {msg["dest_uid"]}\n'
        output += f'Timestamp: {msg["timestamp"].decode()}\n'
        output += f'Subject: {msg["subject"]}\n'
        output += f'Body: {msg["body"]}'
        print(output)

    def parse_output_action(self, server_response):
        try:
            if (server_response is not None):
                msg_data = server_response["data"]
                match server_response["id"]:
                    case "1":
                        self.reply_success(msg_data)
                    case "2":
                        self.reply_fail(msg_data)
                    case "3":
                        self.reply_ask_queue(msg_data)
                    case "4":
                        self.reply_get_msg(msg_data)
                    case _:
                        raise Exception("Input unrecognized")
        
        except Exception as e:
            sys.stderr.write("\n" + str(e) + "MSG RELAY SERVICE: response error!\n")
            exit(1)

def help_instructions():
        help = """
    Help: 
        "-user" (before other commands): specify user data path
        "send <UID> <SUBJECT>: send message with subject <SUBJECT> to user with id <UID>
        "askqueue": get list of unread messages
        "getmsg <NUM>": get message with num <NUM> in queue
        """
        return help
