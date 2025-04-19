from cryptography.hazmat.primitives.serialization import pkcs12

def mkpair(x, y):
    """produz uma byte-string contendo o tuplo '(x,y)' ('x' e 'y' são byte-strings)"""
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y


def unpair(xy):
    """extrai componentes de um par codificado com 'mkpair'"""
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

#Load user private key, user certificate, ca certificate from keystore
def get_userdata(p12_fname, password):
    try:
        with open(p12_fname, "rb") as f:
            p12 = f.read()
        (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
        return (private_key, user_cert, ca_cert)
    except Exception as e:
        print(f"Error loading key and certificates: {e}")
        return None
