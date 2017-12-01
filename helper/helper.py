import PyKCS11
from random import randint
from Crypto.PublicKey import RSA

import templates

def _get_pubkey_pem(session, key_handle):
    """
    Utility function for converting a PKCS#11 key handle to a PEM form RSA public key
    """
    print('Retrieving public key PEM')

    attrs = self.session.getAttributeValue(key_handle, templates.RSA_PUBLIC_ATTRS)
    attr_dict = dict(zip(templates.RSA_PUBLIC_ATTRS, attrs))
    pubkey_obj = None

    m = attr_dict[PyKCS11.CKA_MODULUS]
    e = attr_dict[PyKCS11.CKA_PUBLIC_EXPONENT]
    if m and e:
        md = _convert_long(m)
        ed = _convert_long(e)
        pubkey_obj = RSA.construct((md, ed))

    return pubkey_obj.exportKey(format="PEM")


def get_logged_in_session(lib_path, token_pass, flag=PyKCS11.CKF_RW_SESSION):
    lib = PyKCS11.PyKCS11Lib()
    lib.load(lib_path)
    session = lib.openSession(lib.getSlotList()[0], flag)
    session.login(lib_pass)
    return session

def generate_keypair(session, priv_label, key_size, alg='rsa', exponent=3):
    """
    Generates a new RSA keypair on the token, returns pem form of the public key
    @priv_label: label for the keys
    @key_size: keysize for the keypair
    @alg: algorithm for the key (effectively ignored atm as we only support RSA)
    returns: Public key string in PEM form
    """

    print('Creating a keypair on HSM with label: %s and size: %s' % (priv_label, key_size))
    key_id = bytes(randint(1, 1000000))
    tmpl_pub = templates.get_public_tmpl(key_size, priv_label, key_id, exponent)
    tmpl_priv = templates.get_private_tmpl(priv_label, key_id)

    pubkey, privkey_handle = session.generateKeyPair(tmpl_pub, tmpl_priv)
    return _get_pubkey_pem(session, pubkey)

def encrypt(session, key_label, payload):
    raise NotImplementedError()
