from picnic_impl import *
from picnic3_impl import *
from picnic_types import *
from constants.lowmc_constants import *
from constants.lowmc_constants_L1 import *
from constants.lowmc_constants_L3 import *
from constants.lowmc_constants_L5 import *


import sys
import os


PICNIC_MAX_LOWMC_BLOCK_SIZE = 32
PICNIC_MAX_PUBLICKEY_SIZE = 2 * PICNIC_MAX_LOWMC_BLOCK_SIZE + 1
PICNIC_MAX_PRIVATEKEY_SIZE = 3 * PICNIC_MAX_LOWMC_BLOCK_SIZE + 2
PICNIC_MAX_SIGNATURE_SIZE = 209522


def random_bytes_default(buf, len):
    """
    Funkcja do generowania losowych bajtów za pomocą BCryptGenRandom w systemie Windows.
    """
    if os.name == 'nt':
        import bcrypt
        buf[:len] = bcrypt.gensalt(len)
    else:
        raise NotImplementedError("Nieobsługiwany system operacyjny.")
    
    

SUPERCOP = False  # Zakładam, że SUPERCOP nie jest dostępne w środowisku Pythona

def random_bytes_supercop(buf, len):
    """
    Funkcja do generowania losowych bajtów za pomocą SUPERCOP.
    Nie jest dostępna w środowisku Pythona.
    """
    pass

if SUPERCOP:
    picnic_random_bytes = random_bytes_supercop
else:
    PICNIC_BUILD_DEFAULT_RNG = 1  # Przypisanie wartości domyślnej, jeśli SUPERCOP nie jest dostępny
    picnic_random_bytes = random_bytes_default


class picnic_params_t(Enum):
    PARAMETER_SET_INVALID = 0,
    Picnic_L1_FS = 1,
    Picnic_L1_UR = 2,
    Picnic_L3_FS = 3,
    Picnic_L3_UR = 4,
    Picnic_L5_FS = 5,
    Picnic_L5_UR = 6,
    Picnic3_L1 = 7,
    Picnic3_L3 = 8,
    Picnic3_L5 = 9,
    Picnic_L1_full = 10,
    Picnic_L3_full = 11,
    Picnic_L5_full = 12,
    PARAMETER_SET_MAX_INDEX = 13

# PARAMETER_SET_INVALID = 0
# Picnic_L1_FS = 1
# Picnic_L1_UR = 2
# Picnic_L3_FS = 3
# Picnic_L3_UR = 4
# Picnic_L5_FS = 5
# Picnic_L5_UR = 6
# Picnic3_L1 = 7
# Picnic3_L3 = 8
# Picnic3_L5 = 9
# Picnic_L1_full = 10
# Picnic_L3_full = 11
# Picnic_L5_full = 12
# PARAMETER_SET_MAX_INDEX = 13

# TRANSFORM_FS = 0
# TRANSFORM_UR = 1
# TRANSFORM_INVALID = 255


class picnic_publickey_t:
    def __init__(self):
        self.params = picnic_params_t.PARAMETER_SET_INVALID
        self.plaintext = bytearray(PICNIC_MAX_LOWMC_BLOCK_SIZE)
        self.ciphertext = bytearray(PICNIC_MAX_LOWMC_BLOCK_SIZE)

class picnic_privatekey_t:
    def __init__(self):
        self.params = picnic_params_t.PARAMETER_SET_INVALID
        self.data = bytearray(PICNIC_MAX_LOWMC_BLOCK_SIZE)
        self.pk = picnic_publickey_t()

def is_valid_params(params):
    if params > 0 and params < picnic_params_t.PARAMETER_SET_MAX_INDEX:
        return 1
    print("INVALID PARAMS\n")
    return 0

def get_transform(parameters):
    switcher = {
        picnic_params_t.Picnic_L1_FS: transform_t.TRANSFORM_FS,
        picnic_params_t.Picnic_L3_FS: transform_t.TRANSFORM_FS,
        picnic_params_t.Picnic_L5_FS: transform_t.TRANSFORM_FS,
        picnic_params_t.Picnic3_L1: transform_t.TRANSFORM_FS,
        picnic_params_t.Picnic3_L3: transform_t.TRANSFORM_FS,
        picnic_params_t.Picnic3_L5: transform_t.TRANSFORM_FS,
        picnic_params_t.Picnic_L1_full: transform_t.TRANSFORM_FS,
        picnic_params_t.Picnic_L3_full: transform_t.TRANSFORM_FS,
        picnic_params_t.Picnic_L5_full: transform_t.TRANSFORM_FS,
        picnic_params_t.Picnic_L1_UR: transform_t.TRANSFORM_UR,
        picnic_params_t.Picnic_L3_UR: transform_t.TRANSFORM_UR,
        picnic_params_t.Picnic_L5_UR: transform_t.TRANSFORM_UR,
    }
    return switcher.get(parameters, transform_t.TRANSFORM_INVALID)

def picnic_get_param_name(parameters):
    switcher = {
        picnic_params_t.Picnic_L1_FS: "Picnic_L1_FS",
        picnic_params_t.Picnic_L1_UR: "Picnic_L1_UR",
        picnic_params_t.Picnic_L3_FS: "Picnic_L3_FS",
        picnic_params_t.Picnic_L3_UR: "Picnic_L3_UR",
        picnic_params_t.Picnic_L5_FS: "Picnic_L5_FS",
        picnic_params_t.Picnic_L5_UR: "Picnic_L5_UR",
        picnic_params_t.Picnic3_L1: "Picnic3_L1",
        picnic_params_t.Picnic3_L3: "Picnic3_L3",
        picnic_params_t.Picnic3_L5: "Picnic3_L5",
        picnic_params_t.Picnic_L1_full: "Picnic_L1_full",
        picnic_params_t.Picnic_L3_full: "Picnic_L3_full",
        picnic_params_t.Picnic_L5_full: "Picnic_L5_full",
    }
    return switcher.get(parameters, "Unknown parameter set")

def get_param_set(picnicParams, paramset):
    # Ustawienie wszystkich pól struktury paramset na 0
    paramset.stateSizeBits = 0
    paramset.numMPCRounds = 0
    paramset.numMPCParties = 0
    paramset.numSboxes = 0
    paramset.numRounds = 0
    paramset.digestSizeBytes = 0
    paramset.numOpenedRounds = 0
    paramset.andSizeBytes = 0
    paramset.stateSizeBytes = 0
    paramset.seedSizeBytes = 0
    paramset.stateSizeWords = 0
    paramset.transform = None
    paramset.saltSizeBytes = 0
    paramset.UnruhGWithoutInputBytes = 0
    paramset.UnruhGWithInputBytes = 0

    pqSecurityLevel = 0

    # Obliczenie rozmiaru struktury paramset w bajtach
    paramsetSize = sys.getsizeof(paramset)


    if picnicParams in [picnic_params_t.Picnic_L1_FS, picnic_params_t.Picnic_L1_UR]:
        pqSecurityLevel = 64
        paramset.stateSizeBits = 128
        paramset.numMPCRounds = 219
        paramset.numMPCParties = 3
        paramset.numSboxes = 10
        paramset.numRounds = 20
        paramset.digestSizeBytes = 32
    elif picnicParams in [picnic_params_t.Picnic_L3_FS, picnic_params_t.Picnic_L3_UR]:
        pqSecurityLevel = 96
        paramset.stateSizeBits = 192
        paramset.numMPCRounds = 329
        paramset.numMPCParties = 3
        paramset.numSboxes = 10
        paramset.numRounds = 30
        paramset.digestSizeBytes = 48
    elif picnicParams in [picnic_params_t.Picnic_L5_FS, picnic_params_t.Picnic_L5_UR]:
        pqSecurityLevel = 128
        paramset.stateSizeBits = 256
        paramset.numMPCRounds = 438
        paramset.numMPCParties = 3
        paramset.numSboxes = 10
        paramset.numRounds = 38
        paramset.digestSizeBytes = 64
    elif picnicParams == picnic_params_t.Picnic3_L1:
        pqSecurityLevel = 64
        paramset.stateSizeBits = 129
        paramset.numMPCRounds = 250
        paramset.numOpenedRounds = 36
        paramset.numMPCParties = 16
        paramset.numSboxes = 43
        paramset.numRounds = 4
        paramset.digestSizeBytes = 32
    elif picnicParams == picnic_params_t.Picnic3_L3:
        pqSecurityLevel = 96
        paramset.stateSizeBits = 192
        paramset.numMPCRounds = 419
        paramset.numOpenedRounds = 52
        paramset.numMPCParties = 16
        paramset.numSboxes = 64
        paramset.numRounds = 4
        paramset.digestSizeBytes = 48
    elif picnicParams == picnic_params_t.Picnic3_L5:
        pqSecurityLevel = 128
        paramset.stateSizeBits = 255
        paramset.numMPCRounds = 601
        paramset.numOpenedRounds = 68
        paramset.numMPCParties = 16
        paramset.numSboxes = 85
        paramset.numRounds = 4
        paramset.digestSizeBytes = 64
    elif picnicParams == picnic_params_t.Picnic_L1_full:
        pqSecurityLevel = 64
        paramset.stateSizeBits = 129
        paramset.numMPCRounds = 219
        paramset.numMPCParties = 3
        paramset.numSboxes = 43
        paramset.numRounds = 4
        paramset.digestSizeBytes = 32
    elif picnicParams == picnic_params_t.Picnic_L3_full:
        pqSecurityLevel = 96
        paramset.stateSizeBits = 192
        paramset.numMPCRounds = 329
        paramset.numMPCParties = 3
        paramset.numSboxes = 64
        paramset.numRounds = 4
        paramset.digestSizeBytes = 48
    elif picnicParams == picnic_params_t.Picnic_L5_full:
        pqSecurityLevel = 128
        paramset.stateSizeBits = 255
        paramset.numMPCRounds = 438
        paramset.numMPCParties = 3
        paramset.numSboxes = 85
        paramset.numRounds = 4
        paramset.digestSizeBytes = 64
    else:
        print(("Unsupported Picnic parameter set (%d). \n" % picnicParams))
        return -1

    paramset.andSizeBytes = numBytes(paramset.numSboxes * 3 * paramset.numRounds)
    paramset.stateSizeBytes = numBytes(paramset.stateSizeBits)
    paramset.seedSizeBytes = numBytes(2 * pqSecurityLevel)
    paramset.stateSizeWords = (paramset.stateSizeBits + WORD_SIZE_BITS - 1) // WORD_SIZE_BITS
    paramset.transform = get_transform(picnicParams)
    paramset.saltSizeBytes = 32  # same for all parameter sets

    if paramset.transform == transform_t.TRANSFORM_UR:
        paramset.UnruhGWithoutInputBytes = paramset.seedSizeBytes + paramset.andSizeBytes
        paramset.UnruhGWithInputBytes = paramset.UnruhGWithoutInputBytes + paramset.stateSizeBytes

    return EXIT_SUCCESS


def picnic_keygen(parameters, pk, sk):
    if not is_valid_params(parameters):
        print("Invalid parameter set")
        return -1

    if pk is None:
        print("public key is NULL")
        return -1

    if sk is None:
        print("private key is NULL")
        return -1

    # Ustawienie wszystkich pól struktury pk i sk na 0
    pk.plaintext = bytearray([0] * len(pk.plaintext))
    pk.ciphertext = bytearray([0] * len(pk.ciphertext))
    sk.data = bytearray([0] * len(sk.data))

    # Pobranie zestawu parametrów
    paramset = paramset_t()
    ret = get_param_set(parameters, paramset)
    if ret != EXIT_SUCCESS:
        print("Failed to initialize parameter set")
        return -1

    sk.params = parameters
    pk.params = parameters

    # Generowanie klucza prywatnego
    if picnic_random_bytes(sk.data, paramset.stateSizeBytes) != 0:
        print("Failed to generate private key")
        return -1
    zeroTrailingBits(sk.data, paramset.stateSizeBits)

    # Generowanie losowego bloku tekstu jawnego
    if picnic_random_bytes(pk.plaintext, paramset.stateSizeBytes) != 0:
        print("Failed to generate plaintext")
        return -1
    zeroTrailingBits(pk.plaintext, paramset.stateSizeBits)

    # Obliczenie szyfrogramu
    LowMCEnc(pk.plaintext, pk.ciphertext, sk.data, paramset)

    # Skopiowanie klucza publicznego do klucza prywatnego
    sk.pk = pk

    return 0

def is_picnic3(params):
    return params in [picnic_params_t.Picnic3_L1, picnic_params_t.Picnic3_L3, picnic_params_t.Picnic3_L5]


def picnic_sign(sk, message, message_len, signature, signature_len):
    paramset = paramset_t()
    ret = get_param_set(sk.params, paramset)
    if ret != EXIT_SUCCESS:
        print(("Failed to initialize parameter set\n"))
        return -1
    
    if not is_picnic3(sk.params):
        sig = signature_t()
        allocateSignature(sig, paramset)
        if sig is None:
            return -1
        
        ret = sign_picnic1(sk.data, sk.pk.ciphertext, sk.pk.plaintext, message, message_len, sig, paramset)
        if ret != EXIT_SUCCESS:
            print(("Failed to create signature\n"))
            freeSignature(sig, paramset)
            return -1
        
        ret = serializeSignature(sig, signature, signature_len[0], paramset)
        if ret == -1:
            print(("Failed to serialize signature\n"))
            freeSignature(sig, paramset)
            return -1
        signature_len[0] = ret
        freeSignature(sig, paramset)
    else:
        sig = signature2_t()
        allocateSignature2(sig, paramset)
        if sig is None:
            return -1
        
        ret = sign_picnic3(sk.data, sk.pk.ciphertext, sk.pk.plaintext, message, message_len, sig, paramset)
        if ret != EXIT_SUCCESS:
            print(("Failed to create signature\n"))
            freeSignature2(sig, paramset)
            return -1
        
        ret = serializeSignature2(sig, signature, signature_len[0], paramset)
        if ret == -1:
            print(("Failed to serialize signature\n"))
            freeSignature2(sig, paramset)
            return -1
        signature_len[0] = ret
        freeSignature2(sig, paramset)
    
    return 0

def picnic_signature_size(parameters):
    paramset = paramset_t()
    ret = get_param_set(parameters, paramset)
    if ret != EXIT_SUCCESS:
        return PICNIC_MAX_SIGNATURE_SIZE
    
    if parameters == picnic_params_t.Picnic3_L1 or parameters == picnic_params_t.Picnic3_L3 or parameters == picnic_params_t.Picnic3_L5:
        u = paramset.numOpenedRounds
        T = paramset.numMPCRounds
        numTreeValues = u * ceil_log2((T + (u - 1)) / u)
        
        proofSize = paramset.seedSizeBytes * ceil_log2(paramset.numMPCParties) + paramset.andSizeBytes + paramset.stateSizeBytes + paramset.digestSizeBytes + paramset.stateSizeBytes + paramset.andSizeBytes
        
        signatureSize = paramset.saltSizeBytes + paramset.digestSizeBytes + numTreeValues * paramset.seedSizeBytes + numTreeValues * paramset.digestSizeBytes + proofSize * u
        return signatureSize
    
    if paramset.transform == transform_t.TRANSFORM_FS:
        return paramset.numMPCRounds * (paramset.digestSizeBytes + paramset.stateSizeBytes + numBytes(3 * paramset.numSboxes * paramset.numRounds) +  2 * paramset.seedSizeBytes) + numBytes(2 * paramset.numMPCRounds) + paramset.saltSizeBytes
    elif paramset.transform == transform_t.TRANSFORM_UR:
        return paramset.numMPCRounds * (paramset.digestSizeBytes + paramset.stateSizeBytes + 2 * numBytes(3 * paramset.numSboxes * paramset.numRounds) +  3 * paramset.seedSizeBytes) + numBytes(2 * paramset.numMPCRounds) + paramset.saltSizeBytes
    else:
        return PICNIC_MAX_SIGNATURE_SIZE
    

def picnic_verify(pk, message, message_len, signature, signature_len):
    ret = 0

    paramset = paramset_t()

    ret = get_param_set(pk.params, paramset)
    if ret != EXIT_SUCCESS:
        print(("Failed to initialize parameter set\n"))
        return -1

    if not is_picnic3(pk.params):
        sig = signature_t()
        allocateSignature(sig, paramset)
        if sig == None:
            return -1

        ret = deserializeSignature(sig, signature, signature_len, paramset)
        if ret != EXIT_SUCCESS:
            print(("Failed to deserialize signature\n"))
            freeSignature(sig, paramset)
            # free(sig)
            return -1

        ret = verify(sig, pk.ciphertext, pk.plaintext, message, message_len, paramset)
        if ret != EXIT_SUCCESS:
            freeSignature(sig, paramset)
            # free(sig)
            return -1

        freeSignature(sig, paramset)
        # free(sig)
    else:
        sig = signature2_t()
        allocateSignature2(sig, paramset)
        if sig == None:
            return -1

        ret = deserializeSignature2(sig, signature, signature_len, paramset)
        if ret != EXIT_SUCCESS:
            print(("Failed to deserialize signature\n"))
            freeSignature2(sig, paramset)
            # free(sig)
            return -1

        ret = verify_picnic3(sig, pk.ciphertext, pk.plaintext, message, message_len, paramset)
        if ret != EXIT_SUCCESS:
            freeSignature2(sig, paramset)
            # free(sig)
            return -1

        freeSignature2(sig, paramset)
        # free(sig)

    return 0


def picnic_write_public_key(key, buf, buflen):
    if key == None or buf == None:
        return -1

    paramset = paramset_t()
    ret = get_param_set(key.params, paramset)
    if ret != EXIT_SUCCESS:
        print(("Failed to initialize parameter set\n"))
        return -1

    keySizeBytes = paramset.stateSizeBytes
    bytesRequired = 1 + 2 * keySizeBytes
    if buflen < bytesRequired:
        return -1

    buf[0] = key.params

    memcpy(buf + 1, key.ciphertext, keySizeBytes)
    memcpy(buf + 1 + keySizeBytes, key.plaintext, keySizeBytes)

    return bytesRequired


def picnic_read_public_key(key, buf, buflen):
    if key == None or buf == None:
        return -1

    if buflen < 1 or not is_valid_params(buf[0]):
        return -1

    key.params = buf[0]

    paramset = paramset_t()
    ret = get_param_set(key.params, paramset)
    if ret != EXIT_SUCCESS:
        print(("Failed to initialize parameter set\n"))
        return -1

    keySizeBytes = paramset.stateSizeBytes
    bytesExpected = 1 + 2 * keySizeBytes
    if buflen < bytesExpected:
        return -1

    memcpy(key.ciphertext, buf + 1, keySizeBytes)
    memcpy(key.plaintext, buf + 1 + keySizeBytes, keySizeBytes)

    if not arePaddingBitsZero(key.ciphertext, paramset.stateSizeBits) or not arePaddingBitsZero(key.plaintext, paramset.stateSizeBits):
        return -1

    return 0

def picnic_write_private_key(key, buf, buflen):
    if key == None or buf == None:
        return -1

    paramset = paramset_t()
    ret = get_param_set(key.params, paramset)
    if ret != EXIT_SUCCESS:
        print(("Failed to initialize paramset set\n"))
        return -1

    n = paramset.stateSizeBytes
    bytesRequired = 1 + 3 * n
    if buflen < bytesRequired:
        print(("buffer provided has %u bytes, but %u are required.\n", buflen, bytesRequired))
        return -1

    buf[0] = key.params

    memcpy(buf + 1, key.data, n)
    memcpy(buf + 1 + n, key.pk.ciphertext, n)
    memcpy(buf + 1 + 2 * n, key.pk.plaintext, n)

    return bytesRequired


def picnic_read_private_key(key, buf, buflen):
    if key == None or buf == None:
        return -1

    if buflen < 1 or not is_valid_params(buf[0]):
        return -1

    key = picnic_privatekey_t()  # Inicjalizacja nowego obiektu picnic_privatekey_t

    key.params = buf[0]
    key.pk.params = buf[0]

    paramset = paramset_t()
    ret = get_param_set(key.params, paramset)
    if ret != EXIT_SUCCESS:
        print(("Failed to initialize paramset set\n"))
        return -1

    n = paramset.stateSizeBytes
    bytesExpected = 1 + 3 * n
    if buflen < bytesExpected:
        return -1

    memcpy(key.data, buf + 1, n)
    memcpy(key.pk.ciphertext, buf + 1 + n, n)
    memcpy(key.pk.plaintext, buf + 1 + 2 * n, n)

    if not arePaddingBitsZero(key.data, paramset.stateSizeBits) or not arePaddingBitsZero(key.pk.ciphertext, paramset.stateSizeBits) or not arePaddingBitsZero(key.pk.plaintext, paramset.stateSizeBits):
        return -1

    return 0


def picnic_validate_keypair(privatekey, publickey):
    paramset = paramset_t()
    ret = get_param_set(publickey.params, paramset)
    if ret != EXIT_SUCCESS:
        return -1

    if privatekey == None or publickey == None:
        return -1

    if privatekey.params != publickey.params:
        return -1

    if not is_valid_params(privatekey.params):
        return -1

    ciphertext = [0x00] * len(publickey.ciphertext)
    LowMCEnc(publickey.plaintext, ciphertext, privatekey.data, paramset)
    if ciphertext != publickey.ciphertext:
        return -1

    return 0


def print_signature2(sigBytes, sigBytesLen, picnic_params):
    sig = signature2_t()
    label = ""

    if picnic_params != picnic_params_t.Picnic3_L1 and picnic_params != picnic_params_t.Picnic3_L3 and picnic_params != picnic_params_t.Picnic3_L5:
        print("Invalid parameter set passed.")
        return

    params = paramset_t()
    ret = get_param_set(picnic_params, params)

    if ret != EXIT_SUCCESS:
        print("Invalid parameters\n")
        return

    allocateSignature2(sig, params)

    ret = deserializeSignature2(sig, sigBytes, sigBytesLen, params)
    if ret != 0:
        print("Invalid signature; deserialization fails\n")
        return

    proofs = sig.proofs

    print("challenge C: ")
    for i in range(params.numOpenedRounds):
        print("%u, " % sig.challengeC[i], end="")
    print("\n")
    print("challenge P: ")
    for i in range(params.numOpenedRounds):
        print("%u, " % sig.challengeP[i], end="")
    print("\n")
    printHex("salt", sig.salt, params.saltSizeBytes)
    printHex("iSeedInfo", sig.iSeedInfo, sig.iSeedInfoLen)
    printHex("cvInfo", sig.cvInfo, sig.cvInfoLen)
    print("\n")

    for i in range(params.numOpenedRounds):
        c = sig.challengeC[i]
        p = sig.challengeP[i]
        print("u = {}, MPC instance index c = {}, unopened party index = {}\n".format(i, c, p))


        printHex("seedInfo", proofs[c].seedInfo, proofs[c].seedInfoLen)
        printHex("aux", proofs[c].aux, params.andSizeBytes)
        label = "C[%u][%u]" % (c, p)
        printHex(label, proofs[c].C, params.digestSizeBytes)
        printHex("masked input", proofs[c].input, params.stateSizeBytes)
        printHex("msgs", proofs[c].msgs, params.stateSizeBytes + params.andSizeBytes)
        print("\n")

    freeSignature2(sig, params)


def print_signature(sigBytes, sigBytesLen, picnic_params):
    sig = signature_t()
    label = bytearray(50)

    if picnic_params == picnic_params_t.Picnic3_L1 or picnic_params == picnic_params_t.Picnic3_L3 or picnic_params == picnic_params_t.Picnic3_L5:
        print_signature2(sigBytes, sigBytesLen, picnic_params)
        return

    params = paramset_t()
    ret = get_param_set(picnic_params, params)

    if ret != EXIT_SUCCESS:
        print("Invalid parameters")
        return

    allocateSignature(sig, params)

    ret = deserializeSignature(sig, sigBytes, sigBytesLen, params)
    if ret != 0:
        print("Invalid signature; deserialization fails")
        return

    proofs = sig.proofs
    challengeBits = bytearray(numBytes(2 * params.numMPCRounds))

    memcpy(challengeBits, sigBytes, numBytes(2 * params.numMPCRounds))
    sigBytes += numBytes(2 * params.numMPCRounds)
    printHex("challenge", challengeBits, numBytes(2 * params.numMPCRounds))

    printHex("salt", sigBytes, params.saltSizeBytes)
    sigBytes += params.saltSizeBytes

    print("\n")

    for i in range(params.numMPCRounds):
        print("Iteration t: {}".format(i))

        challenge = getChallenge(challengeBits, i)
        print("e_{}: {}".format(i, challenge))

        memcpy(proofs[i].view3Commitment, sigBytes, params.digestSizeBytes)
        sigBytes += params.digestSizeBytes
        label = "b_{}".format(i)
        printHex(label, proofs[i].view3Commitment, params.digestSizeBytes)

        if params.transform == transform_t.TRANSFORM_UR:
            view3UnruhLength = params.UnruhGWithInputBytes if challenge == 0 else params.UnruhGWithoutInputBytes
            memcpy(proofs[i].view3UnruhG, sigBytes, view3UnruhLength)
            sigBytes += view3UnruhLength
            label = "G_{}".format(i)
            printHex(label, proofs[i].view3UnruhG, view3UnruhLength)

        memcpy(proofs[i].communicatedBits, sigBytes, params.andSizeBytes)
        sigBytes += params.andSizeBytes
        printHex("transcript", proofs[i].communicatedBits, params.andSizeBytes)

        memcpy(proofs[i].seed1, sigBytes, params.seedSizeBytes)
        sigBytes += params.seedSizeBytes
        printHex("seed1", proofs[i].seed1, params.seedSizeBytes)

        memcpy(proofs[i].seed2, sigBytes, params.seedSizeBytes)
        sigBytes += params.seedSizeBytes
        printHex("seed2", proofs[i].seed2, params.seedSizeBytes)

        if challenge == 1 or challenge == 2:
            memcpy(proofs[i].inputShare, sigBytes, params.stateSizeBytes)
            sigBytes += params.stateSizeBytes
            printHex("inputShare", proofs[i].inputShare, params.stateSizeBytes)

        print("\n")

    freeSignature(sig, params)
