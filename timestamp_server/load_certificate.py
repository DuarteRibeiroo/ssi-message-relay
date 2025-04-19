import os
import sys

from common.commonFunc import *

#Load server private key, certificate and ca certificate from pre-defined keystore file
current_dir = os.path.dirname(os.path.abspath(__file__))
p12_file_path = os.path.join('projCA', 'MSG_TIMESTAMP.p12')


key_cert_data = get_userdata(p12_file_path,None)
if (key_cert_data is not None):
    server_private_key, server_certificate, ca_certificate = key_cert_data
else:
    print("Error loading key and certificates")
    exit()

SERVER_PRIVATE_KEY = server_private_key
SERVER_CERTIFICATE = server_certificate
CA_CERTIFICATE = ca_certificate
