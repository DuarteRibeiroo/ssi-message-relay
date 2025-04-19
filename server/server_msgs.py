#### Classes utilzadas pelo servidor para gerir mensagens de clientes

#objetos guardados pelo servidor em memória
class Stored_Msg:
	def __init__(self, num, src_uid, dest_uid, timestamp, timestamp_sig, body_hash, subject, body):
		self.data = {
			"num": num,
			"src_uid": src_uid,
			"dest_uid": dest_uid,
			"timestamp": timestamp,
			"timestamp_sig": timestamp_sig,
			"body_hash" : body_hash,
			"subject": subject,
			"body": body
		}
	
	def __str__(self):
		output = f'Num: {self.data["num"]}\n'
		output += f'From: {self.data["src_uid"]}\n'
		output += f'To: {self.data["dest_uid"]}\n'
		output += f'Timestamp: {self.data["timestamp"].decode()}\n'
		output += f'Subject: {self.data["subject"]}\n'
		output += f'Body: {self.data["body"]}\n'
		return output

#mensagem que servidor envia ao cliente
class Serv_To_Cli_Msg:
	def __init__(self, msg_type, data):
		self.id = msg_type
		self.data = data

	@staticmethod
	#mensagem a dizer se pedido foi ou não bem sucedido
	def reply_success_action(is_Success,data={}):
		if is_Success is True:
			msg_type = "1"
		else:
			msg_type= "2"
		
		return Serv_To_Cli_Msg(
			msg_type,
			data
		)

	@staticmethod
    #mensagens nao lidas da queue do user
	def reply_ask_queue_msg(msg_queue):
		result_str = ""
		for msg in msg_queue:
			data = msg.data
			result_str += f'{data["num"]}:{data["src_uid"]}:{data["timestamp"]}:{data["subject"]}\n' # converter já aqui em string, ou devia ser do lado do cliente?
		return Serv_To_Cli_Msg("3", {"queue":result_str})

	@staticmethod
    #dados inteiros de mensagem
	def reply_get_msg_msg(msg, src_PK,src_uid):
		return Serv_To_Cli_Msg("4", {"msg": msg.data, "src_CRT": src_PK, "src_uid": src_uid})
	
	def __str__(self):
		return f"Message Type: {self.id}\nData: {self.data}"