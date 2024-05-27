import sys
from hashlib import shake_128, shake_256
import hashlib
from typing import List

# from picnic_impl import paramset_t

from classes import *


MAX_DIGEST_SIZE = 64

HASH_PREFIX_NONE = -1
HASH_PREFIX_0 = 0
HASH_PREFIX_1 = 1
HASH_PREFIX_2 = 2
HASH_PREFIX_3 = 3
HASH_PREFIX_4 = 4
HASH_PREFIX_5 = 5

class HashInstance:
    def __init__(self):
        self.ctx = hashlib.sha256()



def HashUpdate(ctx, data: List[int] | int, byteLen: int) -> None:
    ctx.update(data)  # Keccak_HashUpdate(ctx, data, byteLen * 8)


def HashInit(ctx, params: paramset_t, hashPrefix: int):
    # todo: tutaj wyszła zmiana api - zamiast update'u ctx jest jego zwracanie
    if params.stateSizeBits == 128 or params.stateSizeBits == 129:  # L1
        ctx = shake_128()
    else:  # L3, L5
        ctx = shake_256()

    if hashPrefix != HASH_PREFIX_NONE:
        HashUpdate(ctx, hashPrefix, 1)

    return ctx


def HashFinal(ctx) -> None:
    ctx.digest()  # Keccak_HashFinal(ctx, NULL)


def HashSqueeze(ctx, digest: List[int], byteLen: int) -> None:
    # todo - nie istnieje w hashlib?
    pass  # Keccak_HashSqueeze(ctx, digest, byteLen * 8)


def toLittleEndian(x: int) -> int:
    if sys.byteorder == "big":
        return (x << 8) | (x >> 8)
    else:
        return x


def fromLittleEndian(x: int) -> int:
    if sys.byteorder == "big":
        return (x << 8) | (x >> 8)
    else:
        return x


def HashUpdateIntLE(ctx, x: int) -> None:
    outputBytesLE = toLittleEndian(x)
    HashUpdate(ctx, outputBytesLE, 2)  # 2 == sizeof(uint16_t)
