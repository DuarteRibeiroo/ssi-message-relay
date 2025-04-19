class Timestamping_Msg:
    def __init__(self, msg_type, data):
        self.id = msg_type
        self.data = data

    @staticmethod
    def request_timestamp_msg(msg_hash):
        return Timestamping_Msg("0", {"hash": msg_hash})

    @staticmethod
    def reply_timestamp_msg(timestamp,signature):
        return Timestamping_Msg("1", {"timestamp": timestamp,"signature": signature})

    @staticmethod
    def reply_timestamp_error_msg():
        return Timestamping_Msg("2", {})


    def __str__(self):
        return f'Msg Type: {self.id}\nData: {self.data}\n'