from cryptography import x509
import datetime


def cert_load(fname):
    """lê certificado de ficheiro"""
    with open(fname, "rb") as fcert:
        cert = x509.load_pem_x509_certificate(fcert.read())
    return cert


def cert_validtime(cert, now=None):
    """valida que 'now' se encontra no período
    de validade do certificado."""
    if now is None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise Exception(
            "Certificate is not valid at this time"
        )


def cert_validsubject(cert, attrs=[]):
    """verifica atributos do campo 'subject'. 'attrs'
    é uma lista de pares '(attr,value)' que condiciona
    os valores de 'attr' a 'value'."""
    # print(cert.subject)
    for attr in attrs:
        if cert.subject.get_attributes_for_oid(attr[0])[0].value != attr[1]:
            raise x509.verification.VerificationError(
                "Certificate subject does not match expected value"
            )


def cert_validexts(cert, policy=[]):
    """valida extensões do certificado.
    'policy' é uma lista de pares '(ext,pred)' onde 'ext' é o OID de uma extensão e 'pred'
    o predicado responsável por verificar o conteúdo dessa extensão."""
    for check in policy:
        ext = cert.extensions.get_extension_for_oid(check[0]).value
        if not check[1](ext):
            raise x509.verification.VerificationError(
                "Certificate extensions does not match expected value"
            )

def validate_cert(ca_cert, certificate_to_validate,name=""):
    try:
        # obs: pressupõe que a cadeia de certificados só contém 2 níveis
        certificate_to_validate.verify_directly_issued_by(ca_cert)
        # verificar período de validade...
        cert_validtime(certificate_to_validate)
        # verificar identidade... (e.g.)

        # não há forma de saber com antecedência qual é a o sujeito?
        if (name != ""):
            cert_validsubject(certificate_to_validate, [(x509.NameOID.PSEUDONYM, name)]) 
        # verificar aplicabilidade... (e.g.)
        # cert_validexts(
        #     cert,
        #     [
        #         (
        #             x509.ExtensionOID.EXTENDED_KEY_USAGE,
        #             lambda e: x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in e,
        #         )
        #     ],
        # )
        # print("Certificate is valid!")
        return True
    except:
        # print("Certificate is invalid!")
        return False