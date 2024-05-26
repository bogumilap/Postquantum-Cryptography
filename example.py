# Example program to demonstrate how to use Picnic signature API
# Reference file:  https://github.com/microsoft/Picnic/blob/master/example.c

import os
import sys
from picnic import *

MSG_LEN = 500

def picnicExample(parameters):
    pk = picnic_publickey_t(parameters, bytearray(PICNIC_MAX_LOWMC_BLOCK_SIZE), bytearray(PICNIC_MAX_LOWMC_BLOCK_SIZE))
    sk = picnic_privatekey_t(parameters, bytearray(PICNIC_MAX_LOWMC_BLOCK_SIZE), pk)

    print(f"Picnic example with parameter set: {picnic_get_param_name(parameters)}")

    print("Generating key... ", end='')
    ret = picnic_keygen(parameters)

    if ret is None:
        print("picnic_keygen failed")
        exit(-1)

    pk, sk = ret
    print("success")

    message = bytearray([0x01] * MSG_LEN)
    signature = None

    signature_len = picnic_signature_size(parameters)
    signature = bytearray(signature_len)
    if signature is None:
        print("failed to allocate signature")
        exit(-1)
    print(f"Max signature length {signature_len} bytes")

    print(f"Signing a {MSG_LEN} byte message... ", end='')

    ret = picnic_sign(sk, message)
    if ret is None:
        print("picnic_sign failed")
        exit(-1)

    signature, signature_len = ret
    print(f"success, signature is {signature_len} bytes")

    if signature_len < picnic_signature_size(parameters):
        try:
            signature = signature[:signature_len]
        except MemoryError:
            print("failed to resize signature")

    print("Verifying signature... ", end='')

    ret = picnic_verify(pk, message, signature)
    if ret != 0:
        print("picnic_verify failed")
        exit(-1)
    print("success")

    print("Testing public key serialization... ")
    pk_buf = bytearray(PICNIC_MAX_PUBLICKEY_SIZE)
    ret = picnic_write_public_key(pk, pk_buf)
    if ret <= 0:
        print("Failed to serialize public key")
        exit(-1)

    pk = picnic_publickey_t(parameters, bytearray(PICNIC_MAX_LOWMC_BLOCK_SIZE), bytearray(PICNIC_MAX_LOWMC_BLOCK_SIZE))

    ret = picnic_read_public_key(pk, pk_buf)
    if ret != 0:
        print("Failed to read public key")
        exit(-1)

    ret = picnic_verify(pk, message, signature)
    if ret != 0:
        print("picnic_verify failed after de-serializing public key")
        exit(-1)
    print("success")

    print("Testing private key serialization... ")
    sk_buf = bytearray(PICNIC_MAX_PRIVATEKEY_SIZE)
    ret = picnic_write_private_key(sk, sk_buf)
    if ret <= 0:
        print("Failed to write private key")
        exit(-1)

    sk = picnic_privatekey_t(parameters, bytearray(PICNIC_MAX_LOWMC_BLOCK_SIZE), pk)
    ret = picnic_read_private_key(sk, sk_buf)
    if ret != 0:
        print("Failed to read private key")
        exit(-1)
    
    ret = picnic_validate_keypair(sk, pk)
    if ret != 0:
        print("Keypair invalid after deserializing private key")
        exit(-1)
    print("success\n")

    return 0

if __name__ == "__main__":
    if len(sys.argv) > 1:
        picnicExample(int(sys.argv[1]))
    else:
        for params in range(1, picnic_params_t.PARAMETER_SET_MAX_INDEX):
            picnicExample(params)

    