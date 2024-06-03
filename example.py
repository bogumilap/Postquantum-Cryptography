# Example program to demonstrate how to use Picnic signature API
# Reference file:  https://github.com/microsoft/Picnic/blob/master/example.c

import os
import sys
from picnic import *
import ctypes

MSG_LEN = 500

def picnicExample(parameters):
    pk = picnic_publickey_t()
    sk = picnic_privatekey_t()

    print(f"Picnic example with parameter set: {picnic_get_param_name(parameters)}")

    print("Generating key... ", end="")
    sys.stdout.flush()
    ret = picnic_keygen(parameters, pk, sk)

    if ret != 0:
        print("picnic_keygen failed")
        sys.exit(-1)
    print("success")

    message = bytearray([0x01] * MSG_LEN)
    signature_len = picnic_signature_size(parameters)
    signature = bytearray(signature_len)

    if not signature:
        print("failed to allocate signature")
        sys.exit(-1)
    print(f"Max signature length {signature_len} bytes")

    print(f"Signing a {MSG_LEN} byte message... ", end="")
    sys.stdout.flush()

    ret = picnic_sign(sk, message, len(message), signature, signature_len)
    if ret != 0:
        print("picnic_sign failed")
        sys.exit(-1)
    print(f"success, signature is {signature_len} bytes")

    if signature_len < picnic_signature_size(parameters):
        signature = signature[:signature_len]

    print("Verifying signature... ", end="")
    sys.stdout.flush()

    ret = picnic_verify(pk, message, len(message), signature, signature_len)
    if ret != 0:
        print("picnic_verify failed")
        sys.exit(-1)
    print("success")

    print("Testing public key serialization... ", end="")
    pk_buf = bytearray(PICNIC_MAX_PUBLICKEY_SIZE)
    ret = picnic_write_public_key(pk, pk_buf, len(pk_buf))
    if ret <= 0:
        print("Failed to serialize public key")
        sys.exit(-1)

    pk = picnic_publickey_t()
    ret = picnic_read_public_key(pk, pk_buf, len(pk_buf))
    if ret != 0:
        print("Failed to read public key")
        sys.exit(-1)

    ret = picnic_verify(pk, message, len(message), signature, signature_len)
    if ret != 0:
        print("picnic_verify failed after de-serializing public key")
        sys.exit(-1)
    print("success")

    print("Testing private key serialization... ", end="")
    sk_buf = bytearray(PICNIC_MAX_PRIVATEKEY_SIZE)
    ret = picnic_write_private_key(sk, sk_buf, len(sk_buf))
    if ret <= 0:
        print("Failed to write private key")
        sys.exit(-1)

    sk = picnic_privatekey_t()
    ret = picnic_read_private_key(sk, sk_buf, len(sk_buf))
    if ret != 0:
        print("Failed to read private key")
        sys.exit(-1)

    ret = picnic_validate_keypair(sk, pk)
    if ret != 0:
        print("Keypair invalid after deserializing private key")
        sys.exit(-1)
    print("success")

    return 0

def main():
    if len(sys.argv) > 1:
        picnicExample(int(sys.argv[1]))
    else:
        for params in range(1, picnic_params_t.PARAMETER_SET_MAX_INDEX.value):
            picnicExample(params)

if __name__ == "__main__":
    main()

    