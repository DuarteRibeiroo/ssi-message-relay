#!/usr/bin/env python3

class Cli_To_Serv_Msg:
    def __init__(self, msg_type, data=None):
        self.id = msg_type
        self.data = data if data is not None else {}

    @staticmethod
    #função de enviar mensagem com assunto .. para user ...
    def create_send_request_msg(dest_uid, subject):
        return Cli_To_Serv_Msg(1, {
            "dest_uid": dest_uid,
            "subject": subject,
            #body irá separadamente para ser encriptado
        })

    @staticmethod
    #função de pedir mensagens nao lidas da queue do user
    def create_ask_queue_msg():
        return Cli_To_Serv_Msg(2, None)

    @staticmethod
    #funcao de ler msg número ... da queue do user
    def create_get_msg_msg(num):
        return Cli_To_Serv_Msg(3, {
            "msg_num": num
		})
    
    def __str__(self):
        return f"Message Type: {self.id}\nData: {self.data}"