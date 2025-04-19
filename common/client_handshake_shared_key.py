
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509


from common.commonFunc import *
from common.validateCert import validate_cert


max_msg_size = 9999

async def setup_shared_key(reader, writer, keystore_path):
    '''
    Protocol is as follows:
    1. Client generates secret and sends server public part of secret
    2. Server generates its own secret, sends it to client along with signing the two public secrets with the certificate's private key and its certificate
    3. Client sends to server signed public secrets and its certificate
    4. Both the client and server (after certificate verification) are sure they are talking to each other and have a shared secret with which they can encrypt messages messages
    '''

    #Predetermined parameters for secret generation
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2

    #Generate private secret
    parameters = dh.DHParameterNumbers(p,g).parameters()
    client_private_secret = parameters.generate_private_key()

    #Extract public secret from private secret and serialize it with PEM
    client_public_secret_bytes = client_private_secret.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    #Send public secret to server
    writer.write(client_public_secret_bytes)

    #Read server public secret, signature and certificate
    message = await reader.read(max_msg_size)

    server_public_secret_bytes,signature_and_cert = unpair(message)
    server_signature,cert = unpair(signature_and_cert)

    #Deserialize server public secret and certificate
    server_public_secret = serialization.load_pem_public_key(server_public_secret_bytes)
    server_certificate = x509.load_pem_x509_certificate(cert)

    #Load client private key, certificate and ca certificate from keystore file
    key_cert_data = get_userdata(keystore_path,None)

    if (key_cert_data is not None):
        client_private_key, client_certificate, ca_certificate = key_cert_data
    else:
        return None
    
    # print("Read keys from keystore")

    #Validate certificate and derive its key
    validate_cert(ca_certificate, server_certificate,'MSG_SERVER')
    server_certificate_public_key = server_certificate.public_key()

    #Verify signature 
    server_certificate_public_key.verify(
        server_signature,
        server_public_secret_bytes + client_public_secret_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    #Sign public secrets with certificate private key
    #Adapted from https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing´
    generated_secrets = client_public_secret_bytes + server_public_secret_bytes
    client_signature = client_private_key.sign(
        generated_secrets,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    message = mkpair(client_signature,client_certificate.public_bytes(serialization.Encoding.PEM))

    #Send public secrets signature and certificate to server
    writer.write(message)

    #Derive shared key from secrets
    shared_secret = client_private_secret.exchange(server_public_secret)

    derived_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        ).derive(shared_secret)
    
    # print(f"Derived key: {derived_secret}")

    return (client_private_key,derived_secret) # returned derived shared key