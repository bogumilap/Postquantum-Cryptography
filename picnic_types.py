from dataclasses import dataclass
from typing import List

# from picnic_impl import paramset_t, numBytes, transform_t, proof_t, signature_t
from picnic_impl import *
from picnic3_impl import *


@dataclass
class randomTape_t:
    tape: List[List[int]]
    pos: int
    nTapes: int


@dataclass
class view_t:
    inputShare: List[int]
    communicatedBits: List[int]
    outputShare: List[int]


@dataclass
class commitments_t:
    hashes: List[List[int]]
    nCommitments: int


# typedef uint8_t** inputs_t;


@dataclass
class msgs_t:
    msgs: List[List[int]]  # One for each player
    pos: int
    unopened: int  # Index of the unopened party, or -1 if all parties opened (when signing)

@dataclass
class inputs_t:
    pass

@dataclass
class g_commitments_t:
    G: List[List[int]]


@dataclass
class seeds_t:
    seed: List[List[int]]
    iSeed: List[int]


@dataclass
class shares_t:
    shares: List[int]
    numWords: int


def allocateShares(count: int) -> shares_t:
    shares = shares_t([0 for _ in range(count)], count)
    return shares

def freeShares(shares):
    del shares.shares
    del shares



# Allocate functions for dynamically sized types
def allocateView(params: paramset_t) -> view_t:
    view = view_t(inputShare=[0 for _ in range(params.stateSizeBytes)],
                  communicatedBits=[0 for _ in range(params.andSizeBytes)],
                  outputShare=[0 for _ in range(params.stateSizeBytes)])
    return view


def getTapeSizeBytes(params: paramset_t) -> int:
    return 2 * params.andSizeBytes


def allocateRandomTape(params: paramset_t) -> randomTape_t:
    tape = randomTape_t(tape=[[] for _ in range(params.numMPCParties)],
                        pos=0,
                        nTapes=params.numMPCParties)
    tapeSizeBytes = getTapeSizeBytes(params)
    slab = [0 for _ in range(tape.nTapes * tapeSizeBytes)]
    slab_start_index = 0
    for i in range(tape.nTapes):
        tape.tape[i] = slab[slab_start_index:]
        slab_start_index += tapeSizeBytes
    return tape


def allocateProof2(params: paramset_t) -> proof2_t:
    proof = proof2_t(seedInfo=None,  # Sign/verify code sets it
                     seedInfoLen=0,
                     C=[0 for _ in range(params.digestSizeBytes)],
                     input=[0 for _ in range(params.stateSizeBytes)],
                     aux=[0 for _ in range(params.andSizeBytes)],
                     msgs=[0 for _ in range(params.andSizeBytes)])
    return proof


def allocateProof(params: paramset_t) -> proof_t:
    proof = proof_t(seed1=[0 for _ in range(params.seedSizeBytes)],
                    seed2=[0 for _ in range(params.seedSizeBytes)],
                    inputShare=[0 for _ in range(params.stateSizeBytes)],
                    communicatedBits=[0 for _ in range(params.andSizeBytes)],
                    view3Commitment=[0 for _ in range(params.digestSizeBytes)],
                    view3UnruhG=[0 for _ in range(params.UnruhGWithInputBytes)] if params.UnruhGWithInputBytes > 0 else None)
    return proof


def allocateSignature(params: paramset_t) -> signature_t:
    signature = signature_t(proofs=[None for _ in range(params.numMPCRounds)],
                            challengeBits=[0 for _ in range(numBytes(2 * params.numMPCRounds))],
                            salt=[0 for _ in range(params.saltSizeBytes)])

    for i in range(params.numMPCRounds):
        signature.proofs[i] = allocateProof(params)
    return signature


def allocateSignature2(params: paramset_t) -> signature2_t:
    signature = signature2_t(salt=[0 for _ in range(params.saltSizeBytes)],
                             iSeedInfo=None,
                             iSeedInfoToken=0,
                             cvInfo=None,
                             cvInfoLen=0,
                             challengeC=[0 for _ in range(params.numOpenedRounds)],
                             challengeP=[0 for _ in range(params.numOpenedRounds)],
                             challengeHash=[0 for _ in range(params.digestSizeBytes)],
                             proofs=[0 for _ in range(params.numMPCRounds)])
    # Individual proofs are allocated during signature generation, only for rounds when neeeded
    return signature


def allocateSeeds(params: paramset_t) -> List[seeds_t]:
    seeds = []
    nSeeds = params.numMPCParties
    slab1 = [0 for _ in range(params.numMPCRounds * nSeeds * params.seedSizeBytes + params.saltSizeBytes)]  # Seeds
    slab2 = [0 for _ in range(params.numMPCRounds * nSeeds + 1 + params.numMPCRounds)]  # pointers to seeds
    slab3 = [0 for _ in range(params.numMPCRounds * params.seedSizeBytes + params.saltSizeBytes)]  # iSeeds, used to derive seeds

    # We need multiple slabs here, because the seeds are generated with one call to the KDF;
    # they must be stored contiguously
    slab1_start_index = 0
    slab2_start_index = 0
    slab3_start_index = 0
    for i in range(params.numMPCRounds):
        seeds.append(seeds_t(seed=slab2[slab2_start_index:], iSeed=slab3[slab3_start_index:]))
        slab2_start_index += nSeeds
        slab3_start_index += params.seedSizeBytes

        for j in range(nSeeds):
            seeds[i].seed[j] = slab1[slab1_start_index:]
            slab1_start_index += params.seedSizeBytes

    # The salt is the last seed value
    # Accessed by seeds[params->numMPCRounds].iSeed
    seeds[params.numMPCRounds].seed = None
    if params.numMPCParties == 3:
        seeds[params.numMPCRounds].iSeed = slab1  # For ZKB parameter sets, the salt must be derived with the seeds
    else:
        seeds[params.numMPCRounds].iSeed = slab3  # For Pincic2 paramter sets, the salt is dervied with the initial seeds

    return seeds


def allocateCommitments(params: paramset_t, numCommitments: int) -> List[commitments_t]:
    nCommitments = numCommitments if numCommitments else params.numMPCParties
    commitments = [commitments_t(hashes=[], nCommitments=nCommitments)
                   for _ in range(params.numMPCRounds)]

    slab = [0 for _ in range(params.numMPCRounds * (nCommitments * params.digestSizeBytes + nCommitments))]
    slab_start_index = 0
    for i in range(params.numMPCRounds):
        commitments[i].hashes = slab  # todo: ???
        slab_start_index += nCommitments

        for j in range(nCommitments):
            commitments[i].hashes[j] = slab[slab_start_index:]
            slab_start_index += params.digestSizeBytes
    return commitments


# Allocate one commitments_t object with capacity for numCommitments values
def allocateCommitments2(params: paramset_t, numCommitments: int) -> commitments_t:
    commitments = commitments_t(hashes=[], nCommitments=numCommitments)

    slab = [0 for _ in range(numCommitments * params.digestSizeBytes + numCommitments)]

    commitments.hashes = [slab]  # todo ???
    slab_start_index = numCommitments

    for i in range(numCommitments):
        commitments.hashes.append(slab[slab_start_index:])
        slab_start_index += params.digestSizeBytes
    return commitments


def allocateInputs(params: paramset_t) -> inputs_t:
    slab = [0 for _ in range(params.numMPCRounds * (params.stateSizeWords * 4 + 1))]

    inputs = [slab]  # todo ???

    slab_start_index = params.numMPCRounds

    for i in range(params.numMPCRounds):
        inputs[i] = slab[slab_start_index:]
        slab_start_index += params.stateSizeWords * 4

    return inputs


def allocateMsgs(params: paramset_t) -> List[msgs_t]:
    msgs = []
    msgsSize = params.andSizeBytes
    slab = [0 for _ in range(params.numMPCRounds * (params.numMPCParties * msgsSize + params.numMPCParties))]
    slab_start_index = 0
    for i in range(params.numMPCRounds):
        # slab_msgs = slab[slab_start_index:]  # todo ???
        slab_msgs = []
        slab_start_index += params.numMPCParties

        for j in range(params.numMPCParties):
            slab_msgs.append(slab)
            slab_start_index += msgsSize

        msg = msgs_t(msgs=slab_msgs, pos=0, unopened=-1)
        msgs.append(msg)
    return msgs


def allocateViews(params: paramset_t) -> List[List[view_t]]:
    # 3 views per round
    views = [[allocateView(params) for _ in range(3)] for _ in range(params.numMPCRounds)]
    return views


def allocateGCommitments(params: paramset_t) -> List[g_commitments_t]:
    gs = None

    if params.transform == transform_t.TRANSFORM_UR:
        gs = [g_commitments_t([]) for _ in range(params.numMPCRounds)]
        slab = [0 for _ in range(params.UnruhGWithInputBytes * params.numMPCRounds * 3)]
        slab_start_index = 0
        for i in range(params.numMPCRounds):
            for j in range(3):
                gs[i].G.append(slab[slab_start_index:])
                slab_start_index += params.UnruhGWithInputBytes
    return gs


# functions to free memory

def freeView(view):
    del view.inputShare
    del view.communicatedBits
    del view.outputShare

def freeRandomTape(tape):
    if tape is not None:
        del tape.tape[0]
        del tape.tape

def freeProof2(proof):
    del proof.seedInfo
    del proof.C
    del proof.input
    del proof.aux
    del proof.msgs

def freeProof(proof):
    del proof.seed1
    del proof.seed2
    del proof.inputShare
    del proof.communicatedBits
    del proof.view3Commitment
    del proof.view3UnruhG

def freeSignature(sig, params):
    for i in range(params.numMPCRounds):
        freeProof(sig.proofs[i])

    del sig.proofs
    del sig.challengeBits
    del sig.salt

def freeSignature2(sig, params):
    del sig.salt
    del sig.iSeedInfo
    del sig.cvInfo
    del sig.challengeC
    del sig.challengeP
    del sig.challengeHash
    for i in range(params.numMPCRounds):
        freeProof2(sig.proofs[i])
    del sig.proofs

def freeSeeds(seeds):
    del seeds[0].seed[0]  # Frees slab1
    del seeds[0].iSeed    # Frees slab3
    del seeds[0].seed     # frees slab2
    del seeds

def freeCommitments(commitments):
    del commitments[0].hashes
    del commitments

def freeCommitments2(commitments):
    if commitments is not None:
        if commitments.hashes is not None:
            del commitments.hashes

def freeInputs(inputs):
    del inputs

def freeMsgs(msgs):
    del msgs[0].msgs
    del msgs

def freeViews(views, params):
    for i in range(params.numMPCRounds):
        for j in range(3):
            freeView(views[i][j])
        del views[i]

    del views

def freeGCommitments(gs):
    if gs is not None:
        del gs[0].G[0]
        del gs
