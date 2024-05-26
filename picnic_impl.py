from dataclasses import dataclass
from enum import Enum
from typing import List

from constants.lowmc_constants import LOWMC_MAX_WORDS, WORD_SIZE_BITS, KMatrix, LMatrix, RConstant
from hash import HashInit, HASH_PREFIX_2, HashUpdate, HashFinal, HashSqueeze, HASH_PREFIX_NONE, HashUpdateIntLE, \
    HASH_PREFIX_4, HASH_PREFIX_0, HASH_PREFIX_5, toLittleEndian, HASH_PREFIX_1
from picnic_types import view_t, commitments_t, g_commitments_t, seeds_t, randomTape_t, allocateRandomTape, \
    allocateView, allocateViews, allocateCommitments, allocateGCommitments, allocateSeeds


class transform_t(Enum):
    TRANSFORM_FS = 0,
    TRANSFORM_UR = 1,
    TRANSFORM_INVALID = 255


@dataclass
class paramset_t:
    numRounds: int
    numSboxes: int
    stateSizeBits: int
    stateSizeBytes: int
    stateSizeWords: int
    andSizeBytes: int
    UnruhGWithoutInputBytes: int
    UnruhGWithInputBytes: int
    numMPCRounds: int  # T
    numOpenedRounds: int  # u
    numMPCParties: int  # N
    seedSizeBytes: int
    saltSizeBytes: int
    digestSizeBytes: int
    transform: transform_t


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
    proofs: List[proof_t]
    challengeBits: List[int]  # has length numBytes(numMPCRounds*2)
    salt: List[int]  # has length saltSizeBytes


VIEW_OUTPUTS = lambda i, j, viewOutputs: viewOutputs[i * 3 + j]


# void printHex(const char* s, const uint8_t* data, size_t len);


def getBit(array: List[int], bitNumber: int) -> int:
    return (array[bitNumber // 8] >> (7 - (bitNumber % 8))) & 0x01


def getBitFromWordArray(array: List[int], bitNumber: int) -> int:
    return getBit(array, bitNumber)


def setBit(bytes: List[int], bitNumber: int, val: int) -> None:
    bytes[bitNumber // 8] = (bytes[bitNumber >> 3] & ~(1 << (7 - (bitNumber % 8)))) | (val << (7 - (bitNumber % 8)))


def setBitInWordArray(array: List[int], bitNumber: int, val: int) -> None:
    setBit(array, bitNumber, val)


def zeroTrailingBits(data: List[int], bitLength: int) -> None:
    byteLength = numBytes(bitLength)
    for i in range(bitLength, byteLength * 8):
        setBit(data, i, 0)


def partity(data: List[int], len: int) -> int:
    x = data[0]

    for i in range(1, len):
        x ^= data[i]

    y = x ^ (x >> 1)
    y ^= (y >> 2)
    y ^= (y >> 4)
    y ^= (y >> 8)
    y ^= (y >> 16)
    return y & 1


def numBytes(numBits: int) -> int:
    return 0 if numBits == 0 else ((numBits - 1) // 8 + 1)


def xor_array(out: List[int], in1: List[int], in2: List[int], length: int) -> None:
    for i in range(length):
        out[i] = in1[i] ^ in2[i]


def xor_three(output: List[int], in1: List[int], in2: List[int], in3: List[int], lenBytes: int) -> None:
    out = output
    wholeWords = lenBytes // 4
    for i in range(wholeWords):
        output[i] = in1[i] ^ in2[i] ^ in3[i]
    for i in range(wholeWords * 4, lenBytes):
        out[i] = in1[i] ^ in2[i] ^ in3[i]


def parity32(x: int) -> int:
    y = x ^ (x >> 1)
    y ^= (y >> 2)
    y ^= (y >> 4)
    y ^= (y >> 8)
    y ^= (y >> 16)
    return y & 1


def matrix_mul(output: List[int], state: List[int], matrix: List[int], params: paramset_t) -> None:
    # Use temp to correctly handle the case when state = output
    temp = [0 for _ in range(LOWMC_MAX_WORDS)]
    wholeWords = params.stateSizeBits // WORD_SIZE_BITS
    for i in range(params.stateSizeBits):
        prod = 0
        for j in range(wholeWords):
            index = i * params.stateSizeWords + j
            prod ^= (state[j] & matrix[index])
        for j in range(wholeWords * WORD_SIZE_BITS, params.stateSizeBits):
            index = i * params.stateSizeWords * WORD_SIZE_BITS + j
            bit = getBitFromWordArray(state, j) & getBitFromWordArray(matrix, index)
            prod ^= bit
        setBit(temp, i, parity32(prod))
    output[:] = temp[:]  # memcpy((uint8_t*)output, (uint8_t*)temp, params->stateSizeWords * sizeof(uint32_t));


def substitution(state: List[int], params: paramset_t) -> None:
    for i in range(0, params.numSboxes * 3, 3):
        a = getBitFromWordArray(state, i + 2)
        b = getBitFromWordArray(state, i + 1)
        c = getBitFromWordArray(state, i)

        setBitInWordArray(state, i + 2, a ^ (b & c))
        setBitInWordArray(state, i + 1, a ^ b ^ (a & c))
        setBitInWordArray(state, i, a ^ b ^ c ^ (a & b))


def LowMCEnc(plaintext: List[int], output: List[int], key: List[int], params: paramset_t) -> None:
    roundKey = [0 for _ in range(LOWMC_MAX_WORDS)]

    if plaintext != output:
        # output will hold the intermediate state
        output[:] = plaintext[:]  # memcpy(output, plaintext, params->stateSizeWords*(sizeof(uint32_t)));

    matrix_mul(roundKey, key, KMatrix(0, params), params)
    xor_array(output, output, roundKey, params.stateSizeWords)

    for r in range(1, params.numRounds):
        matrix_mul(roundKey, key, KMatrix(r, params), params)
        substitution(output, params)
        matrix_mul(output, output, LMatrix(r - 1, params), params)
        xor_array(output, output, RConstant(r - 1, params), params.stateSizeWords)
        xor_array(output, output, roundKey, params.stateSizeWords)


def createRandomTape(seed: List[int], salt: List[int], roundNumber: int, playerNumber: int,
                     tape: List[int], tapeLengthBytes: int, params: paramset_t) -> bool:
    ctx = None

    if tapeLengthBytes < params.digestSizeBytes:
        return False

    # Hash the seed and a constant, store the result in tape.
    ctx = HashInit(None, params, HASH_PREFIX_2)
    HashUpdate(ctx, seed, params.seedSizeBytes)
    HashFinal(ctx)
    HashSqueeze(ctx, tape, params.digestSizeBytes)

    # Expand the hashed seed, salt, round and player indices, and output length to create the tape.
    HashInit(ctx, params, HASH_PREFIX_NONE)  # todo: HashInit zwraca nowy ctx - nie będzie zawierał poprzedniego
    HashUpdate(ctx, tape, params.digestSizeBytes)  # Hash the hashed seed
    HashUpdate(ctx, salt, params.saltSizeBytes)
    HashUpdateIntLE(ctx, roundNumber)
    HashUpdateIntLE(ctx, playerNumber)
    HashUpdateIntLE(ctx, tapeLengthBytes)
    HashFinal(ctx)
    HashSqueeze(ctx, tape, tapeLengthBytes)

    return True


def mpc_xor(state: List[List[int]], in_state: List[List[int]], len: int, players: int) -> None:
    for i in range(players):
        xor_array(state[i], state[i], in_state[i], len)


def mpc_xor_constant(state: List[List[int]], in_state: List[int], len: int) -> None:
    """Compute the XOR of in with the first state vectors."""
    xor_array(state[0], state[0], in_state, len)


def mpc_xor_constant_verify(state: List[List[int]], in_state: List[int], len: int, challenge: int) -> None:
    # During verify, where the first share is stored in state depends on the challenge
    if challenge == 0:
        xor_array(state[0], state[0], in_state, len)
    elif challenge == 2:
        xor_array(state[1], state[1], in_state, len)


def Commit(seed: List[int], view: view_t, hash: List[int], params: paramset_t) -> None:
    ctx = None

    # Hash the seed, store result in `hash`
    ctx = HashInit(ctx, params, HASH_PREFIX_4)
    HashUpdate(ctx, seed, params.seedSizeBytes)
    HashFinal(ctx)
    HashSqueeze(ctx, hash, params.digestSizeBytes)

    # Compute H_0(H_4(seed), view)
    ctx = HashInit(ctx, params, HASH_PREFIX_0)  # todo: HashInit tworzy nowy ctx
    HashUpdate(ctx, hash, params.digestSizeBytes)
    HashUpdate(ctx, view.inputShare, params.stateSizeBytes)
    HashUpdate(ctx, view.communicatedBits, params.andSizeBytes)
    HashUpdate(ctx, view.outputShare, params.stateSizeBytes)
    HashFinal(ctx)
    HashSqueeze(ctx, hash, params.digestSizeBytes)


def G(viewNumber: int, seed: List[int], view: view_t, output: List[int], params: paramset_t) -> None:
    """This is the random "permuatation" function G for Unruh's transform"""
    ctx = None
    outputBytes = params.seedSizeBytes + params.andSizeBytes

    # Hash the seed with H_5, store digest in output
    ctx = HashInit(ctx, params, HASH_PREFIX_5)
    HashUpdate(ctx, seed, params.seedSizeBytes)
    HashFinal(ctx)
    HashSqueeze(ctx, output, params.digestSizeBytes)

    # Hash H_5(seed), the view, and the length
    ctx = HashInit(ctx, params, HASH_PREFIX_NONE)  # todo: HashInit
    HashUpdate(ctx, output, params.digestSizeBytes)
    if viewNumber == 2:
        HashUpdate(ctx, view.inputShare, params.stateSizeBytes)
        outputBytes += params.stateSizeBytes
    HashUpdate(ctx, view.communicatedBits, params.andSizeBytes)

    outputBytesLE = toLittleEndian(outputBytes)
    HashUpdate(ctx, outputBytesLE, 2)
    HashFinal(ctx)
    HashSqueeze(ctx, output, outputBytes)


def setChallenge(challenge: List[int], round: int, trit: int) -> None:
    # challenge must have length numBytes(numMPCRounds*2)
    # 0 <= index < numMPCRounds
    # trit must be in {0,1,2}
    setBit(challenge, 2 * round, trit & 1)
    setBit(challenge, 2 * round + 1, (trit >> 1) & 1)


def getChallenge(challenge: List[int], round: int) -> int:
    return (getBit(challenge, 2 * round + 1) << 1) | getBit(challenge, 2 * round)


def H3(circuitOutput: List[int], plaintext: List[int], viewOutputs: List[List[int]],
       as_commitments: List[commitments_t], challengeBits: List[int], salt: List[int],
       message: List[int], messageByteLength: int, gs: List[g_commitments_t], params: paramset_t) -> None:
    hash = [0 for _ in range(params.digestSizeBytes)]
    ctx = None

    # Depending on the number of rounds, we might not set part of the last
    # byte, make sure it's always zero.
    challengeBits[numBytes(params.numMPCRounds * 2) - 1] = 0

    ctx = HashInit(ctx, params, HASH_PREFIX_1)

    # Hash the output share from each view
    for i in range(params.numMPCRounds):
        for j in range(3):
            HashUpdate(ctx, VIEW_OUTPUTS(i, j, viewOutputs), params.stateSizeBytes)

    # Hash all the commitments C
    for i in range(params.numMPCRounds):
        for j in range(3):
            HashUpdate(ctx, as_commitments[i].hashes[j], params.digestSizeBytes)

    # Hash all the commitments G
    if params.transform == transform_t.TRANSFORM_UR:
        for i in range(params.numMPCRounds):
            for j in range(3):
                view3UnruhLength = params.UnruhGWithInputBytes if j == 2 else params.UnruhGWithoutInputBytes
                HashUpdate(ctx, gs[i].G[j], view3UnruhLength)

    # Hash the public key
    HashUpdate(ctx, circuitOutput, params.stateSizeBytes)
    HashUpdate(ctx, plaintext, params.stateSizeBytes)

    # Hash the salt & message
    HashUpdate(ctx, salt, params.saltSizeBytes)
    HashUpdate(ctx, message, messageByteLength)

    HashFinal(ctx)
    HashSqueeze(ctx, hash, params.digestSizeBytes)

    # Convert hash to a packed string of values in {0,1,2}
    round = 0
    while True:
        for i in range (params.digestSizeBytes):
            byte = hash[i]
            # iterate over each pair of bits in the byte
            for j in range(0, 8, 2):
                bitPair = (byte >> (6 - j)) & 0x03
                if bitPair < 3:
                    setChallenge(challengeBits, round, bitPair)
                    round += 1
                    if round == params.numMPCRounds:
                        return

        # We need more bits; hash set hash = H_1(hash)
        HashInit(ctx, params, HASH_PREFIX_1)
        HashUpdate(ctx, hash, params.digestSizeBytes)
        HashFinal(ctx)
        HashSqueeze(ctx, hash, params.digestSizeBytes)


# Caller must allocate the first parameter
def prove(proof: proof_t, challenge: int, seeds: seeds_t, views: List[view_t], commitments: commitments_t,
          gs: g_commitments_t, params: paramset_t) -> None:
    if challenge == 0:
        proof.seed1[:] = seeds.seed[0][:]  # memcpy(proof->seed1, seeds->seed[0], params->seedSizeBytes);
        proof.seed2[:] = seeds.seed[1][:]  # memcpy(proof->seed2, seeds->seed[1], params->seedSizeBytes);
    elif challenge == 1:
        proof.seed1[:] = seeds.seed[1][:]  # memcpy(proof->seed1, seeds->seed[1], params->seedSizeBytes);
        proof.seed2[:] = seeds.seed[2][:]  # memcpy(proof->seed2, seeds->seed[2], params->seedSizeBytes);
    elif challenge == 2:
        proof.seed1[:] = seeds.seed[2][:]  # memcpy(proof->seed1, seeds->seed[2], params->seedSizeBytes);
        proof.seed2[:] = seeds.seed[0][:]  # memcpy(proof->seed2, seeds->seed[0], params->seedSizeBytes);

    if challenge == 1 or challenge == 2:
        proof.inputShare[:] = views[2].inputShare[:]

    proof.communicatedBits[:] = views[(challenge + 1) % 3].communicatedBits[:]

    proof.view3Commitment[:] = commitments.hashes[(challenge + 2) % 3][:]

    if params.transform == transform_t.TRANSFORM_UR:
        proof.view3UnruhG[:] = gs.G[(challenge + 2) % 3][:]


def mpc_AND_verify(in1: List[int], in2: List[int], out: List[int],
                   rand: randomTape_t, view1: view_t, view2: view_t) -> None:
    r = [getBit(rand.tape[0], rand.pos), getBit(rand.tape[1], rand.pos)]

    out[0] = (in1[0] & in2[1]) ^ (in1[1] & in2[0]) ^ (in1[0] & in2[0]) ^ r[0] ^ r[1]
    setBit(view1.communicatedBits, rand.pos, out[0])
    out[1] = getBit(view2.communicatedBits, rand.pos)

    rand.pos += 1


def mpc_substitution_verify(state: List[List[int]], rand: randomTape_t, view1: view_t,
                            view2: view_t, params: paramset_t) -> None:
    for i in range(0, params.numSboxes * 3, 3):
        a = [0, 0]
        b = [0, 0]
        c = [0, 0]

        for j in range(2):
            a[j] = getBitFromWordArray(state[j], i + 2)
            b[j] = getBitFromWordArray(state[j], i + 1)
            c[j] = getBitFromWordArray(state[j], i)

        ab = [0, 0]
        bc = [0, 0]
        ca = [0, 0]

        mpc_AND_verify(a, b, ab, rand, view1, view2)
        mpc_AND_verify(b, c, bc, rand, view1, view2)
        mpc_AND_verify(c, a, ca, rand, view1, view2)

        for j in range(2):
            setBitInWordArray(state[j], i + 2, a[j] ^ (bc[j]))
            setBitInWordArray(state[j], i + 1, a[j] ^ b[j] ^ (ca[j]))
            setBitInWordArray(state[j], i, a[j] ^ b[j] ^ c[j] ^ (ab[j]))


def mpc_matrix_mul(output: List[list[int]], state: List[List[int]], matrix: List[int],
                   params: paramset_t, players: int) -> None:
    for player in range(players):
        matrix_mul(output[player], state[player], matrix, params)


def mpc_LowMC_verify(view1: view_t, view2: view_t, tapes: randomTape_t, tmp: List[int],
                     plaintext: List[int], params: paramset_t, challenge: int) -> None:
    state = []
    keyShares = []
    roundKey = []

    for i in range(4 * params.stateSizeWords * 4):
        tmp[i] = 0

    roundKey[0] = tmp
    roundKey[1] = roundKey[0] + params.stateSizeWords
    state[0] = roundKey[1] + params.stateSizeWords
    state[1] = state[0] + params.stateSizeWords

    mpc_xor_constant_verify(state, plaintext, params.stateSizeWords, challenge)

    keyShares[0] = view1.inputShare
    keyShares[1] = view2.inputShare

    mpc_matrix_mul(roundKey, keyShares, KMatrix(0, params), params, 2)
    mpc_xor(state, roundKey, params.stateSizeWords, 2)

    for r in range(1, params.numRounds + 1):
        mpc_matrix_mul(roundKey, keyShares, KMatrix(r, params), params, 2)
        mpc_substitution_verify(state, tapes, view1, view2, params)
        mpc_matrix_mul(state, state, LMatrix(r - 1, params), params, 2)
        mpc_xor_constant_verify(state, RConstant(r - 1, params), params.stateSizeWords, challenge)
        mpc_xor(state, roundKey, params.stateSizeWords, 2)

    view1.outputShare[:] = state[0][:]
    view2.outputShare[:] = state[1][:]


def verifyProof(proof: proof_t, view1: view_t, view2: view_t,
                challenge: int, salt: List[int], roundNumber: int, tmp: List[int],
                plaintext: List[int], tape: randomTape_t, params: paramset_t) -> None:
    view2.communicatedBits[:] = proof.communicatedBits[:]
    tape.pos = 0

    status = False
    match challenge:
        case 0:
            # in this case, both views' inputs are derivable from the input share
            status = createRandomTape(proof.seed1, salt, roundNumber, 0, tmp,
                                      params.stateSizeBytes + params.andSizeBytes, params)
            view1.inputShare[:] = tmp[:params.stateSizeBytes]
            tape.tape[0][:] = tmp[params.stateSizeBytes:params.andSizeBytes]
            status = status and createRandomTape(proof.seed2, salt, roundNumber, 1, tmp,
                                                 params.stateSizeBytes + params.andSizeBytes, params)
            if status:
                view2.inputShare[:] = tmp[:params.stateSizeBytes]
                tape.tape[1][:] = tmp[params.stateSizeBytes:params.andSizeBytes]
        case 1:
            # in this case view2's input share was already given to us explicitly as
            # it is not computable from the seed. We just need to compute view1's input from
            # its seed
            status = createRandomTape(proof.seed1, salt, roundNumber, 1, tmp,
                                      params.stateSizeBytes + params.andSizeBytes, params)
            view1.inputShare[:] = tmp[:params.stateSizeBytes]
            tape.tape[0][:] = tmp[params.stateSizeBytes:params.andSizeBytes]
            status = status and createRandomTape(proof.seed2, salt, roundNumber, 2, tape.tape[1],
                                                 params.andSizeBytes, params)
            if status:
                view2.inputShare[:] = proof.inputShare[:params.stateSizeBytes]
        case 2:
            # in this case view1's input share was already given to us explicitly as
            # it is not computable from the seed. We just need to compute view2's input from
            # its seed
            status = createRandomTape(proof.seed1, salt, roundNumber, 2, tape.tape[0],
                                      params.andSizeBytes, params)
            view1.inputShare[:] = proof.inputShare[:params.stateSizeBytes]
            status = status and createRandomTape(proof.seed2, salt, roundNumber, 0, tmp,
                                                 params.stateSizeBytes + params.andSizeBytes, params)
            if status:
                view2.inputShare[:] = tmp[:params.stateSizeBytes]
                tape.tape[1] = tmp[params.stateSizeBytes:params.andSizeBytes]

    if not status:
        print("Failed to generate random tapes, signature verification will fail (but signature may actually be valid)")

    # When input shares are read from the tapes, and the length is not a whole number of bytes, the trailing bits must be zero
    zeroTrailingBits(view1.inputShare, params.stateSizeBits)
    zeroTrailingBits(view2.inputShare, params.stateSizeBits)

    mpc_LowMC_verify(view1, view2, tape, tmp, plaintext, params, challenge)


def verify(sig: signature_t, pubKey: List[int], plaintext: List[int], message: List[int],
           messageByteLength: int, params: paramset_t) -> int:
    as_commitments = allocateCommitments(params, 0)
    gs = allocateGCommitments(params)

    viewOutputs = [0 for _ in range(params.numMPCRounds * 3 * 4)]
    proofs = sig.proofs

    received_challengebits = sig.challengeBits
    status = 0
    computed_challengebits = None
    view3Slab = None

    tmp = [0 for _ in range(max([6 * params.stateSizeBytes, params.stateSizeBytes + params.andSizeBytes]))]

    tape = allocateRandomTape(params)

    view1s = [allocateView(params) for _ in range(params.numMPCRounds)]  # malloc(params->numMPCRounds * sizeof(view_t));
    view2s = [allocateView(params) for _ in range(params.numMPCRounds)]  # malloc(params->numMPCRounds * sizeof(view_t));

    # Allocate a slab of memory for the 3rd view's output in each round
    view3Slab = [0 for _ in range(params.stateSizeBytes)]
    view3Output = view3Slab  # pointer into the slab to the current 3rd view

    for i in range(params.numMPCRounds):
        verifyProof(proofs[i], view1s[i], view2s[i],
                    getChallenge(received_challengebits, i), sig.salt, i,
                    tmp, plaintext, tape, params)

        # create ordered array of commitments with order computed based on the challenge
        # check commitments of the two opened views
        challenge = getChallenge(received_challengebits, i)
        Commit(proofs[i].seed1, view1s[i], as_commitments[i].hashes[challenge], params)
        Commit(proofs[i].seed2, view2s[i], as_commitments[i].hashes[(challenge + 1) % 3], params)
        as_commitments[i].hashes[(challenge + 2) % 3][:] = proofs[i].view3Commitment[:params.digestSizeBytes]

        if params.transform == transform_t.TRANSFORM_UR:
            G(challenge, proofs[i].seed1, view1s[i], gs[i].G[challenge], params)
            G((challenge + 1) % 3, proofs[i].seed2, view2s[i], gs[i].G[(challenge + 1) % 3], params)
            view3UnruhLength = params.UnruhGWithInputBytes if challenge == 0 else params.UnruhGWithoutInputBytes
            gs[i].G[(challenge + 2) % 3][:] = proofs[i].view3UnruhG[:view3UnruhLength]

        viewOutputs[i * 3 + challenge] = view1s[i].outputShare  # VIEW_OUTPUTS(i, challenge) = view1s[i].outputShare;
        viewOutputs[i * 3 + (challenge + 1) % 3] = view2s[i].outputShae  # VIEW_OUTPUTS(i, (challenge + 1) % 3) = view2s[i].outputShare;
        xor_three(view3Output, view1s[i].outputShare,  view2s[i].outputShare, pubKey, params.stateSizeBytes)
        viewOutputs[i * 3 + ((challenge + 2) % 3)] = view3Output  # VIEW_OUTPUTS(i, (challenge + 2) % 3) = view3Output;
        view3Output = view3Output + params.stateSizeBytes

    computed_challengebits = []

    H3(pubKey, plaintext, viewOutputs, as_commitments,
       computed_challengebits, sig.salt, message, messageByteLength, gs, params)
    if computed_challengebits is not None and \
        received_challengebits[:numBytes(2 * params.numMPCRounds)] != \
            computed_challengebits[:numBytes(2 * params.numMPCRounds)]:
        print("Invalid signature. Did not verify")
        status = 1

    return status


# Functions implementing Sign

def mpc_AND(in1: List[int], in2: List[int], out: List[int], rand: randomTape_t, views: List[view_t]) -> None:
    r = [getBit(rand.tape[0], rand.pos), getBit(rand.tape[1], rand.pos), getBit(rand.tape[2], rand.pos)]

    for i in range(3):
        out[i] = (in1[i] & in2[(i + 1) % 3]) ^ (in1[(i + 1) % 3] & in2[i]) ^ (in1[i] & in2[i]) ^ r[i] ^ r[(i + 1) % 3]
        setBit(views[i].communicatedBits, rand.pos, out[i])

    rand.pos += 1


def mpc_substitution(state: List[List[int]], rand: randomTape_t, views: List[view_t], params: paramset_t) -> None:
    a = [0 for _ in range(3)]
    b = [0 for _ in range(3)]
    c = [0 for _ in range(3)]
    ab = [0 for _ in range(3)]
    bc = [0 for _ in range(3)]
    ca = [0 for _ in range(3)]

    for i in range(0, params.numSboxes * 3, 3):
        for j in range(3):
            a[j] = getBitFromWordArray(state[j], i + 2)
            b[j] = getBitFromWordArray(state[j], i + 1)
            c[j] = getBitFromWordArray(state[j], i)

        mpc_AND(a, b, ab, rand, views)
        mpc_AND(b, c, bc, rand, views)
        mpc_AND(c, a, ca, rand, views)

        for j in range(3):
            setBitInWordArray(state[j], i + 2, a[j] ^ (bc[j]))
            setBitInWordArray(state[j], i + 1, a[j] ^ b[j] ^ (ca[j]))
            setBitInWordArray(state[j], i, a[j] ^ b[j] ^ c[j] ^ (ab[j]))


def mpc_LowMC(tapes: randomTape_t, views: List[view_t], plaintext: List[int],
              slab: List[int], params: paramset_t) -> None:
    keyShares = [[] for _ in range(3)]
    state = [[] for _ in range(3)]
    roundKey = [[] for _ in range(3)]

    for i in range(6 * params.stateSizeWords * 4):
        slab[i] = 0x00
    roundKey[0] = slab[:]
    roundKey[1] = slab[params.stateSizeWords:]
    roundKey[2] = roundKey[1][params.stateSizeWords:]
    state[0] = roundKey[2][params.stateSizeWords:]
    state[1] = state[0][params.stateSizeWords:]
    state[2] = state[1][params.stateSizeWords:]

    for i in range(3):
        keyShares[i] = views[i].inputShare
    mpc_xor_constant(state, plaintext, params.stateSizeWords)
    mpc_matrix_mul(roundKey, keyShares, KMatrix(0, params), params, 3)
    mpc_xor(state, roundKey, params.stateSizeWords, 3)

    for r in range(1, params.numRounds + 1):
        mpc_matrix_mul(roundKey, keyShares, KMatrix(r, params), params, 3)
        mpc_substitution(state, tapes, views, params)
        mpc_matrix_mul(state, state, LMatrix(r - 1, params), params, 3)
        mpc_xor_constant(state, RConstant(r - 1, params), params.stateSizeWords)
        mpc_xor(state, roundKey, params.stateSizeWords, 3)

    for i in range(3):
        views[i].outputShare[:] = state[i][:params.stateSizeBytes]


# #ifdef PICNIC_BUILD_DEFAULT_RNG
# int random_bytes_default(uint8_t* buf, size_t len)
# {
#
# #if defined(__LINUX__)
#     FILE* urandom = fopen("/dev/urandom", "r");
#     if (urandom == NULL) {
#         return -1;
#     }
#
#     if (fread(buf, sizeof(uint8_t), len, urandom) != len) {
#         return -2;
#     }
#     fclose(urandom);
#
#     return 0;
#
# #elif defined(__WINDOWS__)
# #ifndef ULONG_MAX
# #define ULONG_MAX 0xFFFFFFFFULL
# #endif
#     if (len > ULONG_MAX) {
#         return -3;
#     }
#
#     if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
#         return -4;
#     }
#     return 0;
# #else
#     #error "If neither __LINUX__ or __WINDOWS__ are defined, you'll have to implement the random number generator"
# #endif
#
# }
# #endif /* PICNIC_BUILD_DEFAULT_RNG */
#
# #ifdef SUPERCOP
# #include "randombytes.h"
# int random_bytes_supercop(uint8_t* buf, size_t len)
# {
#     randombytes(buf, len); /* returns void */
#     return 0;
# }
# #endif /* SUPERCOP */


def computeSeeds(privateKey: List[int], publicKey: List[int], plaintext: List[int],
                 message: List[int], messageByteLength: int, params: paramset_t) -> List[seeds_t]:
    ctx = None
    allSeeds = allocateSeeds(params)

    ctx = HashInit(ctx, params, HASH_PREFIX_NONE)
    HashUpdate(ctx, privateKey, params.stateSizeBytes)
    HashUpdate(ctx, message, messageByteLength)
    HashUpdate(ctx, publicKey, params.stateSizeBytes)
    HashUpdate(ctx, plaintext, params.stateSizeBytes)
    HashUpdateIntLE(ctx, params.stateSizeBits)
    HashFinal(ctx)

    # Derive the N*T seeds + 1 salt
    HashSqueeze(ctx, allSeeds[0].seed[0], params.seedSizeBytes *
                (params.numMPCParties * params.numMPCRounds) + params.saltSizeBytes)

    return allSeeds


def sign_picnic1(privateKey: List[int], pubKey: List[int], plaintext: List[int], message: List[int],
                 messageByteLength: int, sig: signature_t, params: paramset_t) -> int:
    # Allocate views and commitments for all parallel iterations
    views = allocateViews(params)
    as_commitments = allocateCommitments(params, 0)
    gs = allocateGCommitments(params)

    # Compute seeds for all parallel iterations
    seeds = computeSeeds(privateKey, pubKey, plaintext, message, messageByteLength, params)

    sig.salt[:] = seeds[params.numMPCRounds].iSeed[:params.saltSizeBytes]

    # Allocate a random tape (re-used per parallel iteration), and a temporary buffer
    tape = allocateRandomTape(params)
    tmp = [0 for _ in range(max([9 * params.stateSizeBytes, params.stateSizeBytes + params.andSizeBytes]))]

    for k in range(params.numMPCRounds):
        # for first two players get all tape INCLUDING INPUT SHARE from seed
        for j in range(2):
            status = createRandomTape(seeds[k].seed[j], sig.salt, k, j, tmp,
                                      params.stateSizeBytes + params.andSizeBytes, params)
            if not status:
                print("createRandomTape failed")
                return 1
            views[k][j].inputShare[:] = tmp[:params.stateSizeBytes]
            zeroTrailingBits(views[k][j].inputShare, params.stateSizeBits)
            tape.tape[j][:] = tmp[params.stateSizeBytes:params.andSizeBytes]

        # Now set third party's wires. The random bits are from the seed, the input is
        # the XOR of other two inputs and the private key
        status = createRandomTape(seeds[k].seed[2], sig.salt, k, 2, tape.tape[2], params.andSizeBytes, params)
        if not status:
            print("createRandomTape failed")
            return 1

        xor_three(views[k][2].inputShare, privateKey, views[k][0].inputShare, views[k][1].inputShare, params.stateSizeBytes)
        tape.pos = 0
        mpc_LowMC(tape, views[k], plaintext, tmp, params)

        temp = [0 for _ in range(LOWMC_MAX_WORDS)]
        xor_three(temp, views[k][0].outputShare, views[k][1].outputShare, views[k][2].outputShare, params.stateSizeBytes)
        if temp[:params.stateSizeBytes] != pubKey[:params.stateSizeBytes]:
            print(f"Simulation failed; output does not match public key (round = {k})")
            return 1

        # Committing
        Commit(seeds[k].seed[0], views[k][0], as_commitments[k].hashes[0], params)
        Commit(seeds[k].seed[1], views[k][1], as_commitments[k].hashes[1], params)
        Commit(seeds[k].seed[2], views[k][2], as_commitments[k].hashes[2], params)

        if params.transform == transform_t.TRANSFORM_UR:
            G(0, seeds[k].seed[0], views[k][0], gs[k].G[0], params)
            G(1, seeds[k].seed[1], views[k][1], gs[k].G[1], params)
            G(2, seeds[k].seed[2], views[k][2], gs[k].G[2], params)

    # Generating challenges
    viewOutputs = [None for _ in range(params.numMPCRounds * 3 * 4)]
    for i in range(params.numMPCRounds):
        for j in range(3):
            viewOutputs[i * 3 + j] = views[i][j].outputShare  # VIEW_OUTPUTS(i, j) = views[i][j].outputShare;

    H3(pubKey, plaintext, viewOutputs, as_commitments,
       sig.challengeBits, sig.salt, message, messageByteLength, gs, params)

    # Packing Z
    for i in range(params.numMPCRounds):
        proof = sig.proofs[i]
        prove(proof, getChallenge(sig.challengeBits, i), seeds[i],
              views[i], as_commitments[i], None if gs is None else gs[i], params)
    return 0


# Serialization functions

def serializeSignature(sig: signature_t, sigBytes: List[int], sigBytesLen: int, params: paramset_t) -> int:
    proofs = sig.proofs
    challengeBits = sig.challengeBits

    # Validate input buffer is large enough
    bytesRequired = numBytes(2 * params.numMPCRounds) + params.saltSizeBytes + params.numMPCRounds * \
                    (2 * params.seedSizeBytes + params.stateSizeBytes + params.andSizeBytes + params.digestSizeBytes)

    if params.transform == transform_t.TRANSFORM_UR:
        bytesRequired += params.UnruhGWithoutInputBytes * params.numMPCRounds

    if sigBytesLen < bytesRequired:
        return -1

    sigBytesBase = sigBytes[:]
    sigBytes_start_index = 0
    sigBytes[sigBytes_start_index:numBytes(2 * params.numMPCRounds)] = challengeBits[:numBytes(2 * params.numMPCRounds)]
    sigBytes_start_index += numBytes(2 * params.numMPCRounds)
    sigBytes[sigBytes_start_index:] = sig.salt[:params.saltSizeBytes]
    sigBytes_start_index += params.saltSizeBytes

    for i in range(params.numMPCRounds):
        challenge = getChallenge(challengeBits, i)
        sigBytes[sigBytes_start_index:sigBytes_start_index + params.digestSizeBytes] = \
            proofs[i].view3Commitment[:params.digestSizeBytes]
        sigBytes_start_index += params.digestSizeBytes

        if params.transform == transform_t.TRANSFORM_UR:
            view3UnruhLength = params.UnruhGWithInputBytes if challenge == 0 else params.UnruhGWithoutInputBytes
            sigBytes[sigBytes_start_index:sigBytes_start_index + view3UnruhLength] = \
                proofs[i].view3UnruhG[:view3UnruhLength]
            sigBytes_start_index += view3UnruhLength

        sigBytes[sigBytes_start_index:] = proofs[i].communicatedBits[:params.andSizeBytes]
        sigBytes_start_index += params.andSizeBytes

        sigBytes[sigBytes_start_index:] = proofs[i].seed1[:params.seedSizeBytes]
        sigBytes_start_index += params.seedSizeBytes

        sigBytes[sigBytes_start_index:] = proofs[i].seed2[:params.seedSizeBytes]
        sigBytes_start_index += params.seedSizeBytes

        if challenge == 1 or challenge == 2:
            sigBytes[sigBytes_start_index:] = proofs[i].inputShare[:params.stateSizeBytes]
            sigBytes_start_index += params.stateSizeBytes

    return len(sigBytes) - len(sigBytesBase)


def computeInputShareSize(challengeBits: List[int], stateSizeBytes: int, params: paramset_t) -> int:
    # When the FS transform is used, the input share is included in the proof
    # only when the challenge is 1 or 2.  When dersializing, to compute the
    # number of bytes expected, we must check how many challenge values are 1
    # or 2. The parameter stateSizeBytes is the size of an input share.
    inputShareSize = 0

    for i in range(params.numMPCRounds):
        challenge = getChallenge(challengeBits, i)
        if challenge == 1 or challenge == 2:
            inputShareSize += stateSizeBytes
    return inputShareSize


def isChallengeValid(challengeBits: List[int], params: paramset_t) -> int:
    for i in range(params.numMPCRounds):
        challenge = getChallenge(challengeBits, i)
        if challenge > 2:
            return 0
    return 1


def arePaddingBitsZero(data: List[int], bitLength: int) -> int:
    byteLength = numBytes(bitLength)
    for i in range(bitLength, byteLength * 8):
        bit_i = getBit(data, i)
        if bit_i != 0:
            return 0
    return 1


def deserializeSignature(sig: signature_t, sigBytes: List[int], sigBytesLen: int, params: paramset_t) -> int:
    proofs = sig.proofs
    challengeBits = sig.challengeBits

    # Validate input buffer is large enough
    if sigBytesLen < numBytes(2 * params.numMPCRounds):  # ensure the input has at least the challenge
        return 1

    inputShareSize = computeInputShareSize(sigBytes, params.stateSizeBytes, params)
    bytesExpected = numBytes(2 * params.numMPCRounds) + params.saltSizeBytes + params.numMPCRounds * \
                    (2 * params.seedSizeBytes + params.andSizeBytes + params.digestSizeBytes) + inputShareSize

    if params.transform == transform_t.TRANSFORM_UR:
        bytesExpected += params.UnruhGWithoutInputBytes * params.numMPCRounds
    if sigBytesLen < bytesExpected:
        return 1

    sigBytes_start_index = 0
    challengeBits[sigBytes_start_index:] = sigBytes[:numBytes(2 * params.numMPCRounds)]
    sigBytes_start_index += numBytes(2 * params.numMPCRounds)

    if not isChallengeValid(challengeBits, params):
        return 1

    sig.salt[:] = sigBytes[sigBytes_start_index:sigBytes_start_index + params.saltSizeBytes]
    sigBytes_start_index += params.saltSizeBytes

    for i in range(params.numMPCRounds):
        challenge = getChallenge(challengeBits, i)

        proofs[i][:] = sigBytes[sigBytes_start_index:sigBytes_start_index + params.digestSizeBytes]
        sigBytes_start_index += params.digestSizeBytes

        if params.transform == transform_t.TRANSFORM_UR:
            view3UnruhLength = params.UnruhGWithInputBytes if challenge == 0 else params.UnruhGWithoutInputBytes
            proofs[i].view3UnruhG[:] = sigBytes[sigBytes_start_index:sigBytes_start_index + view3UnruhLength]
            sigBytes_start_index += view3UnruhLength

        proofs[i].communicatedBits[:] = sigBytes[sigBytes_start_index:sigBytes_start_index + params.andSizeBytes]
        sigBytes_start_index += params.andSizeBytes

        proofs[i].seed1[:] = sigBytes[sigBytes_start_index:sigBytes_start_index + params.seedSizeBytes]
        sigBytes_start_index += params.seedSizeBytes

        proofs[i].seed2[:] = sigBytes[sigBytes_start_index:sigBytes_start_index + params.seedSizeBytes]
        sigBytes_start_index += params.seedSizeBytes

        if challenge == 1 or challenge == 2:
            proofs[i].inputShare[:] = sigBytes[sigBytes_start_index:sigBytes_start_index + params.stateSizeBytes]
            sigBytes_start_index += params.stateSizeBytes
            if not arePaddingBitsZero(proofs[i].inputShare, params.stateSizeBits):
                return 1

    return 0
