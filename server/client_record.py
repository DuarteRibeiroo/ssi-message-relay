from server.server_msgs import *

#Registos de um cliente no servidor
class Client:
    def __init__(self, uid, certificate):
        self.uid = uid
        self.certificate = certificate # certificate of public key used to create handshake with server
        self.unread_msgs = dict()
        self.read_msgs = dict()
        self.msg_count = 0

    #adicionar mensagem nova à queue de cliente
    def add_msg(self, src_uid, timestamp,timestamp_sig, body_hash, subject, body):
        self.msg_count += 1
        new_msg = Stored_Msg(self.msg_count, src_uid,self.uid,timestamp,timestamp_sig,body_hash,subject,body)
        self.unread_msgs[str(self.msg_count)] = new_msg
    
    #ler mensagem de cliente, pode ser unread ou read;
    ## se for unread, passa para a read queue
    def read_msg(self,msg_id):
        msg = self.unread_msgs.get(msg_id,None)
        if (msg is not None): # se mensagem era unread
            del self.unread_msgs[msg_id]
            self.read_msgs[msg_id] = msg
        else: # se mensagem n foi encontrada em unread
            msg = self.read_msgs.get(msg_id,None)

        return msg

    def get_unread_queue(self):
        return list(self.unread_msgs.values())
    
    def __str__(self):
        # Constructing the string representation of the object
        output = ">>>Client\n"
        output += f"Client UID: {self.uid}\n"
        output += f"Unread Messages:\n"
        for msg in self.unread_msgs.values():
            output += msg.__str__()
        output += f"Read Messages:\n"
        for msg in self.read_msgs.values():
            output += msg.__str__()
        output += f"Message count: {self.msg_count}"
        return output