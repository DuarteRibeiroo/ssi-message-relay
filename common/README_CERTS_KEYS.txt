Como gerar certificados - 
    todos os ficheiros criados vão para a pasta "otherCA/"

## CRIAR CERT CA  ###
(se não especificar <CA_PSEUDONYM>, fica "MSG_CA" por padrão):
>> python3 common/generate_certs.py ca <CA_PSEUDONYM>

## CRIAR KEYSTORE SERVER  ###
(se não especificar <CA_PSEUDONYM>, fica "MSG_CA" por padrão):
(se não especificar <SERVER_PSEUDONYM>, fica "MSG_SERVER" por padrão):
>> python3 common/generate_certs.py server <CA_PSEUDONYM> <SERVER_PSEUDONYM>

## CRIAR KEYSTORE CLIENTE  ###
(se não especificar <CA_PSEUDONYM>, fica "MSG_CA" por padrão):
(se não especificar <CLIENT_PSEUDONYM>, fica "MSG_CLI1" por padrão):
>> python3 common/generate_certs.py client <CA_PSEUDONYM> <CLIENT_PSEUDONYM>
