import PyKCS11
from binascii import unhexlify

RSA_PUBLIC_ATTRS = [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT]

ALL_CERT_ATTRS = [PyKCS11.CKA_CERTIFICATE_TYPE,
                  PyKCS11.CKA_CLASS,
                  PyKCS11.CKA_ID,
                  PyKCS11.CKA_ISSUER,
                  PyKCS11.CKA_LABEL,
                  PyKCS11.CKA_MODIFIABLE,
                  PyKCS11.CKA_PRIVATE,
                  PyKCS11.CKA_SERIAL_NUMBER,
                  PyKCS11.CKA_SUBJECT,
                  PyKCS11.CKA_TOKEN,
                  PyKCS11.CKA_VALUE]

def get_public_tmpl(keysize, label, key_id, exponent):
    """
    Returns a template for creating a public key on the HSM
    @keysize : size of the key
    @label : label for the key
    @key_id: CKA_ID for the key (as integer)
    returns: array of tuples suitable for passing to PyKCS11
    """

    return [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
        (PyKCS11.CKA_MODULUS_BITS, keysize),
        (PyKCS11.CKA_PUBLIC_EXPONENT, long_to_bytes(exponent)),
        (PyKCS11.CKA_LABEL, label),
        (PyKCS11.CKA_ID, bytes(key_id))
    ]


def get_private_tmpl(priv_label, key_id):
    """
    Returns a template for creating a private key on the HSM
    @priv_label: label for the key
    @key_id: CKA_ID for the key (as integer)
    returns: array of tuples suitable for passing to PyKCS11
    """
    return [
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_LABEL, priv_label),
        (PyKCS11.CKA_ID, bytes(key_id))
    ]


def get_x509_template(label, cert, subject, key_id):
    """
    Returns a template for creating a certificate object on the HSM
    @label: label for the object, should match the private key
    @cert: raw DER-form certificate data
    @subject: raw DER-form subject data
    @key_id: CKA_ID for the cert (as integer)
    returns: array of tuples suitable for passing to PyKCS11
    """
    cert_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_LABEL, label),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509),
        (PyKCS11.CKA_MODIFIABLE, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_VALUE, cert),  # must be BER-encoded
        (PyKCS11.CKA_SUBJECT, subject),  # must be set and DER, see Table 24, X.509 Certificate Object Attributes


def long_to_bytes(val):
    width = val.bit_length()
    width += 8 - ((width % 8) or 8)
    fmt = '%%0%dx' % (width // 4)
    s = unhexlify(fmt % val)

    return s
