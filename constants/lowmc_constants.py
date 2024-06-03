from typing import List, Optional

from constants.lowmc_constants_L1 import LMatrix_L1, LMatrix_L1_full, LMatrix_L1_inv, \
    KMatrix_L1, KMatrix_L1_full, KMatrix_L1_inv, \
    RConstants_L1, RConstants_L1_full
from constants.lowmc_constants_L3 import LMatrix_L3, LMatrix_L3_full, LMatrix_L3_inv, \
    KMatrix_L3, KMatrix_L3_full, KMatrix_L3_inv, \
    RConstants_L3, RConstants_L3_full
# noinspection PyUnresolvedReferences
from constants.lowmc_constants_L5 import LMatrix_L5, LMatrix_L5_full, LMatrix_L5_inv, \
    KMatrix_L5, KMatrix_L5_full, KMatrix_L5_inv, \
    RConstants_L5, RConstants_L5_full
# from picnic_impl import paramset_t

from classes import *
from constants.matrices_t import * 


WORD_SIZE_BITS = 32  # the word size for the implementation. Not a LowMC parameter
LOWMC_MAX_STATE_SIZE = 64
LOWMC_MAX_WORDS = LOWMC_MAX_STATE_SIZE // 4
LOWMC_MAX_KEY_BITS = 256
LOWMC_MAX_AND_GATES = 3 * 38 * 10 + 4  # Rounded to nearest byte

ROW_SIZE = lambda m: m.columns
MAT_SIZE = lambda m: m.rows * ROW_SIZE(m)

GET_MAT = lambda m, r: m.data[r * MAT_SIZE(m):(r+1) * MAT_SIZE(m)]


def LMatrix(round: int, params: paramset_t) -> Optional[List[int]]:
    """Return the LowMC linear matrix for this round"""
    if params.stateSizeBits == 128:
        return GET_MAT(LMatrix_L1, round)
    elif params.stateSizeBits == 129:
        return GET_MAT(LMatrix_L1_full, round)
    elif params.stateSizeBits == 192:
        if params.numRounds == 4:
            return GET_MAT(LMatrix_L3_full, round)
        else:
            return GET_MAT(LMatrix_L3, round)
    elif params.stateSizeBits == 255:
        return GET_MAT(LMatrix_L5_full, round)
    elif params.stateSizeBits == 256:
        return GET_MAT(LMatrix_L5, round)
    else:
        return None


def LMatrixInv(round: int, params: paramset_t) -> Optional[List[int]]:
    """Return the LowMC inverse linear layer matrix for this round"""
    if params.stateSizeBits == 129:
        return GET_MAT(LMatrix_L1_inv, round)
    elif params.stateSizeBits == 192 and params.numRounds == 4:
        return GET_MAT(LMatrix_L3_inv, round)
    elif params.stateSizeBits == 255:
        return GET_MAT(LMatrix_L5_inv, round)
    else:
        return None


def KMatrix(round: int, params: paramset_t) -> Optional[List[int]]:
    """Return the LowMC key matrix for this round"""
    if params.stateSizeBits == 128:
        return GET_MAT(KMatrix_L1, round)
    elif params.stateSizeBits == 129:
        return GET_MAT(KMatrix_L1_full, round)
    elif params.stateSizeBits == 192:
        if params.numRounds == 4:
            return GET_MAT(KMatrix_L3_full, round)
        else:
            return GET_MAT(KMatrix_L3, round)
    elif params.stateSizeBits == 255:
        return GET_MAT(KMatrix_L5_full, round)
    elif params.stateSizeBits == 256:
        return GET_MAT(KMatrix_L5, round)
    else:
        return None


def KMatrixInv(round: int, params: paramset_t) -> Optional[List[str]]:
    """Return the LowMC inverse key matrix for this round"""
    assert round == 0
    if params.stateSizeBits == 129:
        return GET_MAT(KMatrix_L1_inv, round)
    elif params.stateSizeBits == 192 and params.numRounds == 4:
        return GET_MAT(KMatrix_L3_inv, round)
    elif params.stateSizeBits == 255:
        return GET_MAT(KMatrix_L5_inv, round)
    else:
        return None


def RConstant(round: int, params: paramset_t) -> Optional[List[int]]:
    """Return the LowMC round constant for this round"""
    if params.stateSizeBits == 128:
        return GET_MAT(RConstants_L1, round)
    elif params.stateSizeBits == 129:
        return GET_MAT(RConstants_L1_full, round)
    elif params.stateSizeBits == 192:
        if params.numRounds == 4:
            return GET_MAT(RConstants_L3_full, round)
        else:
            return GET_MAT(RConstants_L3, round)
    elif params.stateSizeBits == 255:
        return GET_MAT(RConstants_L5_full, round)
    elif params.stateSizeBits == 256:
        return GET_MAT(RConstants_L5, round)
    else:
        return None
