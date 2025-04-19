#!/usr/bin/env python3
import sys
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import pkcs12

def generate_ca_cert(ca_pseudonym="MSG_CA"):

    # Generate priv key for CA
    ca_priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Create CA certificate
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Minho"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidade do Minho"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI MSG RELAY SERVICE"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MSG RELAY SERVICE CA"),
        x509.NameAttribute(NameOID.PSEUDONYM, ca_pseudonym)
    ])

    ca_cert = x509.CertificateBuilder(
        ).subject_name(
            ca_subject
        ).issuer_name(
            ca_subject # CA emite o seu próprio certificado
        ).public_key(
            ca_priv_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now()
        ).not_valid_after(
            datetime.datetime.now() + datetime.timedelta(days=90)
        # meti as mesmas extensões que estavam no CA fornecido (acho?)
        ).add_extension( 
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).add_extension(
            x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True,
        ).sign(
            private_key=ca_priv_key,
            algorithm=hashes.SHA256(),
        )

    # Save to file the certificate
    with open(f"otherCA/{ca_pseudonym}.crt", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    with open(f"otherCA/{ca_pseudonym}.key", "wb") as f:
        ca_private_key_bytes = ca_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        f.write(ca_private_key_bytes)

# Function to generate .p12 file with priv_key,cert, ca_cert, entity can be client or server
def generate_other_cert(ca_pseudonym, other_pseudonym="", isServer=False):

    with open(f"otherCA/{ca_pseudonym}.key", "rb") as ca_priv_key_file:
        ca_priv_key = serialization.load_pem_private_key(
        ca_priv_key_file.read(),
        password=None
        )

    with open(f"otherCA/{ca_pseudonym}.crt", "rb") as ca_cert_file:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read())

    #nomes standard se não forem definidos
    if (isServer and other_pseudonym == ""):
        other_pseudonym = "MSG_SERVER"
    elif other_pseudonym == "":
        other_pseudonym = "MSG_CLI1"

    # Generate a private key
    entity_priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    entity_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Minho"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidade do Minho"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI MSG RELAY SERVICE"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MSG RELAY SERVICE CA"),
        x509.NameAttribute(NameOID.PSEUDONYM, other_pseudonym)
    ])

    entity_cert = x509.CertificateBuilder().subject_name(
        entity_subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        entity_priv_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now()
    ).not_valid_after(
        datetime.datetime.now() + datetime.timedelta(days=90)
    ).add_extension( 
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True,
    )
    
    # se for servidor, usage para servidor
    if (isServer):
        entity_cert = entity_cert.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False
        )

    #senao para cliente
    else:
        entity_cert = entity_cert.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False
        )
    
    entity_cert = entity_cert.sign(
        private_key=ca_priv_key,
        algorithm=hashes.SHA256(),
    )

    # Serialize entity_priv_key, entity_cert, ca_cert in PKCS#12 archive
    p12_data = serialization.pkcs12.serialize_key_and_certificates(
        name= other_pseudonym.encode(),
        encryption_algorithm=NoEncryption(), # sem password por simplicidade
        key=entity_priv_key,
        cert=entity_cert,
        cas=[ca_cert]
    )

    # Write the PKCS#12 archive to a file
    with open(f"otherCA/{other_pseudonym}.p12", "wb") as f:
        f.write(p12_data)

def redirect_input():
    match sys.argv[1]:
        case "ca":
            ca_pseudonym = "MSG_CA"
            if len(sys.argv) == 3:
                ca_pseudonym = sys.argv[2]
            generate_ca_cert(ca_pseudonym)
        case "server":
            ca_pseudonym = "MSG_CA"
            server_pseudonym = "MSG_SERVER"
            if len(sys.argv) >= 3:
                ca_pseudonym = sys.argv[2]
            if len(sys.argv) == 4:
                server_pseudonym = sys.argv[3]

            generate_other_cert(ca_pseudonym,server_pseudonym,True) 
        case "client":
            ca_pseudonym = "MSG_CA"
            client_pseudonym = "MSG_SERVER"
            if len(sys.argv) >= 3:
                ca_pseudonym = sys.argv[2]
            if len(sys.argv) == 4:
                client_pseudonym = sys.argv[3]
                
            generate_other_cert(ca_pseudonym,client_pseudonym,False) 
        case _:
            raise Exception("Invalid input, read common/README.txt instructions")

if __name__ == '__main__':
    redirect_input()