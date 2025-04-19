import os 
from cryptography import x509

from server.client_record import *
from common.commonFunc import *

class Server:
    def __init__(self):
        self.clients = dict() # lista de Client. cada um tem as mensagens destinadas a ele la dentro
    
    #adicionar registo de cliente ao servidor
    def add_client(self, uid, certificate=None):
        if uid not in self.clients:
            self.clients[uid] = Client(uid, certificate)


    #devolver dados de cliente se existir ou None
    def get_client(self,uid):
        return self.clients.get(uid,None)
    
    #carregar todos os clientes do sistema, assumimos que todos os clientes do sistema já estão registados no sistema
    def load_all_clients(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        directory = 'projCA'

        files = os.listdir(directory)
        for file in files:
        # Check if file matches the pattern
            if file.startswith('MSG_CLI') and file.endswith('.p12'):
                p12_file_path = os.path.join(directory, file)
                key_cert_data = get_userdata(p12_file_path,None)
                if (key_cert_data is not None):
                    client_private_key, client_certificate, ca_certificate = key_cert_data

                #save client pseudonym
                for name in client_certificate.subject:
                    if name.oid == x509.NameOID.PSEUDONYM:
                        self.add_client(name.value, client_certificate)
                        break