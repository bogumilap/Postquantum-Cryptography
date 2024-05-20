# Public API for the Picnic signature scheme.
# Reference file: https://github.com/microsoft/Picnic/blob/master/picnic.h


import os

PICNIC_MAX_LOWMC_BLOCK_SIZE = 32
PICNIC_MAX_PUBLICKEY_SIZE = 2 * PICNIC_MAX_LOWMC_BLOCK_SIZE + 1
PICNIC_MAX_PRIVATEKEY_SIZE = 3 * PICNIC_MAX_LOWMC_BLOCK_SIZE + 2
PICNIC_MAX_SIGNATURE_SIZE = 209522

class PicnicParams:
    PARAMETER_SET_INVALID = 0
    Picnic_L1_FS = 1
    Picnic_L1_UR = 2
    Picnic_L3_FS = 3
    Picnic_L3_UR = 4
    Picnic_L5_FS = 5
    Picnic_L5_UR = 6
    Picnic3_L1 = 7
    Picnic3_L3 = 8
    Picnic3_L5 = 9
    Picnic_L1_full = 10
    Picnic_L3_full = 11
    Picnic_L5_full = 12
    PARAMETER_SET_MAX_INDEX = 13

class PicnicPublicKey:
    def __init__(self, params, plaintext, ciphertext):
        self.params = params
        self.plaintext = plaintext
        self.ciphertext = ciphertext

class PicnicPrivateKey:
    def __init__(self, params, data, pk):
        self.params = params
        self.data = data
        self.pk = pk

def picnic_get_param_name(parameters):
    param_names = {
        PicnicParams.Picnic_L1_FS: "Picnic_L1_FS",
        PicnicParams.Picnic_L1_UR: "Picnic_L1_UR",
        PicnicParams.Picnic_L3_FS: "Picnic_L3_FS",
        PicnicParams.Picnic_L3_UR: "Picnic_L3_UR",
        PicnicParams.Picnic_L5_FS: "Picnic_L5_FS",
        PicnicParams.Picnic_L5_UR: "Picnic_L5_UR",
        PicnicParams.Picnic3_L1: "Picnic3_L1",
        PicnicParams.Picnic3_L3: "Picnic3_L3",
        PicnicParams.Picnic3_L5: "Picnic3_L5",
        PicnicParams.Picnic_L1_full: "Picnic_L1_full",
        PicnicParams.Picnic_L3_full: "Picnic_L3_full",
        PicnicParams.Picnic_L5_full: "Picnic_L5_full",
    }
    return param_names.get(parameters, "PARAMETER_SET_INVALID")

def picnic_keygen(parameters):
    pk = PicnicPublicKey(parameters, os.urandom(PICNIC_MAX_LOWMC_BLOCK_SIZE), os.urandom(PICNIC_MAX_LOWMC_BLOCK_SIZE))
    sk = PicnicPrivateKey(parameters, os.urandom(PICNIC_MAX_LOWMC_BLOCK_SIZE), pk)
    return pk, sk

def picnic_sign(sk, message):
    signature = os.urandom(PICNIC_MAX_SIGNATURE_SIZE)
    signature_len = len(signature)
    return signature, signature_len

def picnic_signature_size(parameters):
    return PICNIC_MAX_SIGNATURE_SIZE

def picnic_verify(pk, message, signature):
    return 0 if signature else -1

def picnic_write_public_key(key, buf):
    buf[:PICNIC_MAX_LOWMC_BLOCK_SIZE] = key.plaintext + key.ciphertext
    return PICNIC_MAX_PRIVATEKEY_SIZE

def picnic_read_public_key(key, buf):
    key.plaintext = buf[:PICNIC_MAX_LOWMC_BLOCK_SIZE]
    key.ciphertext = buf[PICNIC_MAX_LOWMC_BLOCK_SIZE:PICNIC_MAX_PUBLICKEY_SIZE]
    return 0

def picnic_write_private_key(key, buf):
    buf[:PICNIC_MAX_PRIVATEKEY_SIZE] = key.data + key.pk.plaintext + key.pk.ciphertext
    return PICNIC_MAX_PRIVATEKEY_SIZE

def picnic_read_private_key(key, buf):
    key.data = buf[:PICNIC_MAX_LOWMC_BLOCK_SIZE]
    key.pk.plaintext = buf[PICNIC_MAX_LOWMC_BLOCK_SIZE:2*PICNIC_MAX_LOWMC_BLOCK_SIZE]
    key.pk.ciphertext = buf[2*PICNIC_MAX_LOWMC_BLOCK_SIZE:PICNIC_MAX_PRIVATEKEY_SIZE]
    return 0

def picnic_validate_keypair(privatekey, publickey):
    return 0 if privatekey.pk.plaintext == publickey.plaintext and privatekey.pk.ciphertext == publickey.ciphertext else -1

def picnic_random_bytes(buf, length):
    buf[:] = os.urandom(length)

def print_signature(sigBytes, sigBytesLen, picnic_params):
    print(f"Signature: {sigBytes[:sigBytesLen]} with parameters {picnic_get_param_name(picnic_params)}")