from dataclasses import dataclass
from enum import Enum
from typing import List
from typing import Optional

class transform_t(Enum):
    TRANSFORM_FS = 0
    TRANSFORM_UR = 1
    TRANSFORM_INVALID = 255


@dataclass
class paramset_t:
    numRounds: int = 0
    numSboxes: int = 0
    stateSizeBits: int = 0
    stateSizeBytes: int = 0
    stateSizeWords: int = 0
    andSizeBytes: int = 0
    UnruhGWithoutInputBytes: int = 0
    UnruhGWithInputBytes: int = 0
    numMPCRounds: int = 0
    numOpenedRounds: int = 0
    numMPCParties: int = 0
    seedSizeBytes: int = 0
    saltSizeBytes: int = 0
    digestSizeBytes: int = 0
    transform: Optional[transform_t] = None


@dataclass
class proof_t:
    seed1: List[int]
    seed2: List[int]
    inputShare: List[int]  # Input share of the party which does not derive it from the seed (not included if challenge is 0)
    communicatedBits: List[int]
    view3Commitment: List[int]
    view3UnruhG: List[int]  # we include the max length, but we will only serialize the bytes we use


@dataclass
class signature_t:
    proofs: List[proof_t] = None
    challengeBits: List[int]  = None# has length numBytes(numMPCRounds*2)
    salt: List[int] = None # has length saltSizeBytes


class proof2_t:
    def __init__(self, seedInfo, seedInfoLen, aux, C, input, msgs):
        self.seedInfo = seedInfo         # Information required to compute the tree with seeds of of all opened parties
        self.seedInfoLen = seedInfoLen   # Length of seedInfo buffer
        self.aux = aux                   # Last party's correction bits; NULL if P[t] == N-1
        self.C = C                       # Commitment to preprocessing step of unopened party
        self.input = input               # Masked input used in online execution
        self.msgs = msgs                 # Broadcast messages of unopened party P[t]

class signature2_t:
    def __init__(self, salt, iSeedInfo, iSeedInfoLen, cvInfo, cvInfoLen, challengeHash, challengeC, challengeP, proofs):
        self.salt = salt
        self.iSeedInfo = iSeedInfo       # Info required to recompute the tree of all initial seeds
        self.iSeedInfoLen = iSeedInfoLen
        self.cvInfo = cvInfo             # Info required to check commitments to views (reconstruct Merkle tree)
        self.cvInfoLen = cvInfoLen
        self.challengeHash = challengeHash
        self.challengeC = challengeC
        self.challengeP = challengeP
        self.proofs = proofs             # One proof for each online execution the verifier checks

def numBytes(numBits: int) -> int:
    return 0 if numBits == 0 else ((numBits - 1) // 8 + 1)