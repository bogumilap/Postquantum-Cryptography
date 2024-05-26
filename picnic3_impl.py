from picnic_impl import *
from picnic import *
from platform import *
import picnic_types
from hash import *
from constants.lowmc_constants import *
from constants.lowmc_constants_L1 import *
from constants.lowmc_constants_L3 import *
from constants.lowmc_constants_L5 import *

import tree

EXIT_SUCCESS = 0
EXIT_FAILURE = 1

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

def printHex(s, data):
    print(f"{s}: ", end="")
    for byte in data:
        print(f"{byte:02X}", end="")
    print()


# Definiowanie makr w Pythonie
def MIN(a, b):
    return a if a < b else b

LOWMC_MAX_AND_GATES = 0  # Należy ustawić odpowiednią wartość
LOWMC_MAX_KEY_BITS = 0   # Należy ustawić odpowiednią wartość

MAX_AUX_BYTES = (LOWMC_MAX_AND_GATES + LOWMC_MAX_KEY_BITS) // 8 + 1

# Implementacja funkcji nlz
def nlz(x):
    if x == 0:
        return 32
    n = 1
    if (x >> 16) == 0:
        n += 16
        x <<= 16
    if (x >> 24) == 0:
        n += 8
        x <<= 8
    if (x >> 28) == 0:
        n += 4
        x <<= 4
    if (x >> 30) == 0:
        n += 2
        x <<= 2
    n -= (x >> 31)
    return n

def ceil_log2(x):
    if x == 0:
        return 0
    return 32 - nlz(x - 1)

# Implementacja funkcji parity16
def parity16(x):
    y = x ^ (x >> 1)
    y ^= (y >> 2)
    y ^= (y >> 4)
    y ^= (y >> 8)
    return y & 1

# Implementacja funkcji createRandomTapes
def createRandomTapes(tapes, seeds, salt, t, params):
    tapeSizeBytes = picnic_types.getTapeSizeBytes(params)
    allocateRandomTape(tapes, params)
    for i in range(params.numMPCParties):
        ctx = HashInstance()
        HashInit(ctx, params, HASH_PREFIX_NONE)
        HashUpdate(ctx, seeds[i], params.seedSizeBytes)
        HashUpdate(ctx, salt, params.saltSizeBytes)
        HashUpdateIntLE(ctx, t)
        HashUpdateIntLE(ctx, i)
        HashFinal(ctx)
        HashSqueeze(ctx, tapes.tape[i], tapeSizeBytes)

# Implementacja funkcji tapesToWord
def tapesToWord(tapes):
    shares = 0
    for i in range(16):
        bit = getBit(tapes.tape[i], tapes.pos)
        setBit(shares, i, bit)
    tapes.pos += 1
    return shares

# Implementacja funkcji tapesToWords
def tapesToWords(shares, tapes):
    for w in range(shares.numWords):
        shares.shares[w] = tapesToWord(tapes)

# Implementacja funkcji tapesToParityBits
def tapesToParityBits(output, outputBitLen, tapes):
    for i in range(outputBitLen):
        setBitInWordArray(output, i, parity16(tapesToWord(tapes)))

# Implementacja funkcji extend
def extend(bit):
    return ~(bit - 1)

# Implementacja funkcji aux_mpc_AND
def aux_mpc_AND(mask_a, mask_b, fresh_output_mask, tapes, params):
    lastParty = params.numMPCParties - 1
    and_helper = tapesToWord(tapes)
    and_helper = parity16(and_helper) ^ getBit(tapes.tape[lastParty], tapes.pos - 1)
    aux_bit = (mask_a & mask_b) ^ and_helper ^ fresh_output_mask
    setBit(tapes.tape[lastParty], tapes.pos - 1, aux_bit)

# Implementacja funkcji aux_mpc_sbox
def aux_mpc_sbox(in_, out, tapes, params):
    for i in range(0, params.numSboxes * 3, 3):
        a = getBitFromWordArray(in_, i + 2)
        b = getBitFromWordArray(in_, i + 1)
        c = getBitFromWordArray(in_, i)

        d = getBitFromWordArray(out, i + 2)
        e = getBitFromWordArray(out, i + 1)
        f = getBitFromWordArray(out, i)

        fresh_output_mask_ab = f ^ a ^ b ^ c
        fresh_output_mask_bc = d ^ a
        fresh_output_mask_ca = e ^ a ^ b

        aux_mpc_AND(a, b, fresh_output_mask_ab, tapes, params)
        aux_mpc_AND(b, c, fresh_output_mask_bc, tapes, params)
        aux_mpc_AND(c, a, fresh_output_mask_ca, tapes, params)

def memcpy(dest, src, n):
    """
    Kopiuje n bajtów danych z obszaru pamięci źródłowej src do obszaru pamięci docelowej dest.
    
    Args:
        dest: Lista lub tablica, do której dane zostaną skopiowane.
        src: Lista lub tablica, z której dane zostaną skopiowane.
        n: Liczba bajtów do skopiowania.
    """
    dest[:n] = src[:n]  # Wycinanie i przypisanie wartości n pierwszych elementów z src do dest


# Implementacja funkcji computeAuxTape
def computeAuxTape(tapes, inputs, params):
    roundKey = [0] * LOWMC_MAX_WORDS
    x = [0] * LOWMC_MAX_WORDS
    y = [0] * LOWMC_MAX_WORDS
    key = [0] * LOWMC_MAX_WORDS
    key0 = [0] * LOWMC_MAX_WORDS

    key0[params.stateSizeWords - 1] = 0
    tapesToParityBits(key0, params.stateSizeBits, tapes)

    # key = key0 x KMatrix[0]^(-1)
    matrix_mul(key, key0, KMatrixInv(0, params), params)

    if inputs is not None:
        memcpy(inputs, key, params.stateSizeBytes)

    for r in range(params.numRounds, 0, -1):
        matrix_mul(roundKey, key, KMatrix(r, params), params)  # roundKey = key * KMatrix(r)
        xor_array(x, x, roundKey, params.stateSizeWords)
        matrix_mul(y, x, LMatrixInv(r - 1, params), params)

        if r == 1:
            # Use key as input
            memcpy(x, key0, params.stateSizeBytes)
        else:
            tapes.pos = params.stateSizeBits * 2 * (r - 1)
            # Read input mask shares from tapes
            tapesToParityBits(x, params.stateSizeBits, tapes)

        tapes.pos = params.stateSizeBits * 2 * (r - 1) + params.stateSizeBits
        aux_mpc_sbox(x, y, tapes, params)

    # Reset the random tape counter so that the online execution uses the
    # same random bits as when computing the aux shares
    tapes.pos = 0

# Implementacja funkcji commit
def commit(digest, seed, aux, salt, t, j, params):
    # Compute C[t][j]; as digest = H(seed||[aux]) aux is optional
    ctx = HashInstance()

    HashInit(ctx, params, HASH_PREFIX_NONE)
    HashUpdate(ctx, seed, params.seedSizeBytes)
    if aux is not None:
        HashUpdate(ctx, aux, params.andSizeBytes)
    HashUpdate(ctx, salt, params.saltSizeBytes)
    HashUpdateIntLE(ctx, t)
    HashUpdateIntLE(ctx, j)
    HashFinal(ctx)
    HashSqueeze(ctx, digest, params.digestSizeBytes)

# Implementacja funkcji commit_h
def commit_h(digest, C, params):
    ctx = HashInstance()

    HashInit(ctx, params, HASH_PREFIX_NONE)
    for i in range(params.numMPCParties):
        HashUpdate(ctx, C.hashes[i], params.digestSizeBytes)
    HashFinal(ctx)
    HashSqueeze(ctx, digest, params.digestSizeBytes)

# Implementacja funkcji commit_v
def commit_v(digest, input, msgs, params):
    ctx = HashInstance()

    HashInit(ctx, params, HASH_PREFIX_NONE)
    HashUpdate(ctx, input, params.stateSizeBytes)
    for i in range(params.numMPCParties):
        msgs_size = numBytes(msgs.pos)
        HashUpdate(ctx, msgs.msgs[i], msgs_size)
    HashFinal(ctx)
    HashSqueeze(ctx, digest, params.digestSizeBytes)

# Implementacja funkcji wordToMsgs
def wordToMsgs(w, msgs, params):
    for i in range(params.numMPCParties):
        w_i = getBit(w, i)
        setBit(msgs.msgs[i], msgs.pos, w_i)
    msgs.pos += 1

def mpc_AND(a, b, mask_a, mask_b, tapes, msgs, params):
    and_helper = tapesToWord(tapes)  # The special mask value setup during preprocessing for each AND gate
    s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper
    if msgs.unopened >= 0:
        unopenedPartyBit = getBit(msgs.msgs[msgs.unopened], msgs.pos)
        setBit(s_shares, msgs.unopened, unopenedPartyBit)

    # Broadcast each share of s
    wordToMsgs(s_shares, msgs, params)

    return parity16(s_shares) ^ (a & b)


def mpc_sbox(state, state_masks, tapes, msgs, params):
    for i in range(0, params.numSboxes * 3, 3):
        a = getBitFromWordArray(state, i + 2)
        mask_a = state_masks.shares[i + 2]

        b = getBitFromWordArray(state, i + 1)
        mask_b = state_masks.shares[i + 1]

        c = getBitFromWordArray(state, i)
        mask_c = state_masks.shares[i]

        ab = mpc_AND(a, b, mask_a, mask_b, tapes, msgs, params)
        bc = mpc_AND(b, c, mask_b, mask_c, tapes, msgs, params)
        ca = mpc_AND(c, a, mask_c, mask_a, tapes, msgs, params)

        d = a ^ bc
        e = a ^ b ^ ca
        f = a ^ b ^ c ^ ab

        setBitInWordArray(state, i + 2, d)
        setBitInWordArray(state, i + 1, e)
        setBitInWordArray(state, i, f)

# # Debugging helper functions (if needed)
# #if 0
# def print_unmasked(label, state, mask_shares, params):
#     tmp = [0] * LOWMC_MAX_WORDS
#     reconstructShares(tmp, mask_shares)
#     xor_array(tmp, tmp, state, params.stateSizeWords)
#     printHex(label, tmp, params.stateSizeBytes)

# def printMsgs(msgs, params):
#     print(f"Msgs: pos = {msgs.pos}, unopened = {msgs.unopened}")
#     for i in range(params.numMPCParties):
#         print(f"tape{i:03} : ", end="")
#         printHex("", msgs.msgs[i], params.andSizeBytes)

# def printTapes(tapes, params):
#     for i in range(params.numMPCParties):
#         print(f"party {i:02}, ", end="")
#         printHex("tape", tapes.tape[i], params.andSizeBytes)
# #endif


def contains(lst, value):
    for i in range(len(lst)):
        if lst[i] == value:
            return 1
    return 0

def indexOf(lst, value):
    for i in range(len(lst)):
        if lst[i] == value:
            return i
    assert False, "indexOf called on list where value is not found. (caller bug)"
    return -1

def getAuxBits(output, tapes, params):
    last = params.numMPCParties - 1
    pos = 0
    n = params.stateSizeBits

    for j in range(params.numRounds):
        for i in range(n):
            setBit(output, pos, getBit(tapes.tape[last], n + n*2*j  + i))
            pos += 1

def setAuxBits(tapes, input, params):
    last = params.numMPCParties - 1
    pos = 0
    n = params.stateSizeBits

    for j in range(params.numRounds):
        for i in range(n):
            setBit(tapes.tape[last], n + n*2*j  + i, getBit(input, pos))
            pos += 1

def simulateOnline(maskedKey, tapes, tmp_shares, msgs, plaintext, pubKey, params):
    ret = 0
    roundKey = [0] * LOWMC_MAX_WORDS
    state = [0] * LOWMC_MAX_WORDS

    matrix_mul(roundKey, maskedKey, KMatrix(0, params), params)        # roundKey = maskedKey * KMatrix[0]
    xor_array(state, roundKey, plaintext, params.stateSizeWords)      # state = plaintext + roundKey

    for r in range(1, params.numRounds + 1):
        tapesToWords(tmp_shares, tapes)
        mpc_sbox(state, tmp_shares, tapes, msgs, params)
        matrix_mul(state, state, LMatrix(r - 1, params), params)       # state = state * LMatrix (r-1)
        xor_array(state, state, RConstant(r - 1, params), params.stateSizeWords)  # state += RConstant
        matrix_mul(roundKey, maskedKey, KMatrix(r, params), params)
        xor_array(state, roundKey, state, params.stateSizeWords)      # state += roundKey

    if state != pubKey:
        ret = -1
        # Debugging statements
        # if DEBUG:
        #     print("%s: output does not match pubKey" % __func__)
        #     printHex("pubKey", pubKey, params.stateSizeBytes)
        #     printHex("output", state, params.stateSizeBytes)
    return ret


def bitsToChunks(chunkLenBits, input, inputLen, chunks):
    if chunkLenBits > inputLen * 8:
        assert False, "Invalid input to bitsToChunks: not enough input"
        return 0
    chunkCount = inputLen * 8 // chunkLenBits

    for i in range(chunkCount):
        chunks[i] = 0
        for j in range(chunkLenBits):
            chunks[i] += getBit(input, i * chunkLenBits + j) << j
            assert chunks[i] < (1 << chunkLenBits)
        chunks[i] = fromLittleEndian(chunks[i])

    return chunkCount

def appendUnique(lst, value, position):
    if position == 0:
        lst[position] = value
        return position + 1

    for i in range(position):
        if lst[i] == value:
            return position
    lst[position] = value
    return position + 1

def expandChallengeHash(challengeHash, challengeC, challengeP, params):
    ctx = HashInstance()
    bitsPerChunkC = ceil_log2(params.numMPCRounds)
    bitsPerChunkP = ceil_log2(params.numMPCParties)
    chunks = [0] * (params.digestSizeBytes * 8 // min(bitsPerChunkC, bitsPerChunkP))
    h = challengeHash[:]

    countC = 0
    while countC < params.numOpenedRounds:
        numChunks = bitsToChunks(bitsPerChunkC, h, params.digestSizeBytes, chunks)
        for i in range(numChunks):
            if chunks[i] < params.numMPCRounds:
                countC = appendUnique(challengeC, chunks[i], countC)
            if countC == params.numOpenedRounds:
                break

        ctx.init(params, HASH_PREFIX_1)
        ctx.update(h, params.digestSizeBytes)
        ctx.final()
        ctx.squeeze(h, params.digestSizeBytes)

    countP = 0

    while countP < params.numOpenedRounds:
        numChunks = bitsToChunks(bitsPerChunkP, h, params.digestSizeBytes, chunks)
        for i in range(numChunks):
            if chunks[i] < params.numMPCParties:
                challengeP[countP] = chunks[i]
                countP += 1
            if countP == params.numOpenedRounds:
                break

        ctx.init(params, HASH_PREFIX_1)
        ctx.update(h, params.digestSizeBytes)
        ctx.final()
        ctx.squeeze(h, params.digestSizeBytes)

    # Note: We always compute h = H(h) after setting C


def HCP(challengeHash, challengeC, challengeP, Ch, hCv, salt, pubKey, plaintext, message, messageByteLength, params):
    ctx = HashInstance()

    assert params.numOpenedRounds < params.numMPCRounds

    ctx.init(params, HASH_PREFIX_NONE)
    for t in range(params.numMPCRounds):
        ctx.update(Ch.hashes[t], params.digestSizeBytes)

    ctx.update(hCv, params.digestSizeBytes)
    ctx.update(salt, params.saltSizeBytes)
    ctx.update(pubKey, params.stateSizeBytes)
    ctx.update(plaintext, params.stateSizeBytes)
    ctx.update(message, messageByteLength)
    ctx.final()
    ctx.squeeze(challengeHash, params.digestSizeBytes)

    if challengeC is not None and challengeP is not None:
        expandChallengeHash(challengeHash, challengeC, challengeP, params)

def getMissingLeavesList(challengeC, params):
    missingLeavesSize = params.numMPCRounds - params.numOpenedRounds
    missingLeaves = [0] * missingLeavesSize
    pos = 0

    for i in range(params.numMPCRounds):
        if not contains(challengeC, params.numOpenedRounds, i):
            missingLeaves[pos] = i
            pos += 1

    return missingLeaves


def verify_picnic3(sig, pubKey, plaintext, message, messageByteLength, params):
    C = allocateCommitments(params, 0)
    Ch = commitments_t()
    Cv = commitments_t()
    msgs = picnic_types.allocateMsgs(params)
    treeCv = tree.createTree(params.numMPCRounds, params.digestSizeBytes)
    challengeHash = [0] * MAX_DIGEST_SIZE
    seeds = [None] * params.numMPCRounds
    tapes = [None] * params.numMPCRounds
    iSeedsTree = tree.createTree(params.numMPCRounds, params.seedSizeBytes)

    ret = tree.reconstructSeeds(iSeedsTree, sig.challengeC, params.numOpenedRounds, sig.iSeedInfo, sig.iSeedInfoLen, sig.salt, 0, params)
    if ret != 0:
        ret = -1
        return ret

    for t in range(params.numMPCRounds):
        if not contains(sig.challengeC, params.numOpenedRounds, t):
            seeds[t] = tree.generateSeeds(params.numMPCParties, tree.getLeaf(iSeedsTree, t), sig.salt, t, params)
        else:
            seeds[t] = tree.createTree(params.numMPCParties, params.seedSizeBytes)
            P_index = indexOf(sig.challengeC, params.numOpenedRounds, t)
            hideList = [sig.challengeP[P_index]]
            ret = tree.reconstructSeeds(seeds[t], hideList, 1, sig.proofs[t].seedInfo, sig.proofs[t].seedInfoLen, sig.salt, t, params)
            if ret != 0:
                print("Failed to reconstruct seeds for round", t)
                return -1

    last = params.numMPCParties - 1
    auxBits = [0] * MAX_AUX_BYTES
    for t in range(params.numMPCRounds):
        createRandomTapes(tapes[t], tree.getLeaves(seeds[t]), sig.salt, t, params)

        if not contains(sig.challengeC, params.numOpenedRounds, t):
            computeAuxTape(tapes[t], None, params)
            for j in range(last):
                commit(C[t].hashes[j], tree.getLeaf(seeds[t], j), None, sig.salt, t, j, params)
            getAuxBits(auxBits, tapes[t], params)
            commit(C[t].hashes[last], tree.getLeaf(seeds[t], last), auxBits, sig.salt, t, last, params)
        else:
            unopened = sig.challengeP[indexOf(sig.challengeC, params.numOpenedRounds, t)]
            for j in range(last):
                if j != unopened:
                    commit(C[t].hashes[j], tree.getLeaf(seeds[t], j), None, sig.salt, t, j, params)
            if last != unopened:
                commit(C[t].hashes[last], tree.getLeaf(seeds[t], last), sig.proofs[t].aux, sig.salt, t, last, params)

            C[t].hashes[unopened] = sig.proofs[t].C

    picnic_types.allocateCommitments2(Cv, params, params.numMPCRounds)
    tmp_shares = picnic_types.allocateShares(params.stateSizeBits)
    for t in range(params.numMPCRounds):
        if contains(sig.challengeC, params.numOpenedRounds, t):
            unopened = sig.challengeP[indexOf(sig.challengeC, params.numOpenedRounds, t)]
            tapeLengthBytes = picnic_types.getTapeSizeBytes(params)
            if unopened != last:
                setAuxBits(tapes[t], sig.proofs[t].aux, params)
            tapes[t].tape[unopened] = [0] * tapeLengthBytes
            msgs[t].msgs[unopened] = sig.proofs[t].msgs
            msgs[t].unopened = unopened

            rv = simulateOnline(sig.proofs[t].input, tapes[t], tmp_shares, msgs[t], plaintext, pubKey, params)
            if rv != 0:
                print("MPC simulation failed for round", t, ", signature invalid")
                picnic_types.freeShares(tmp_shares)
                return -1
            commit_v(Cv.hashes[t], sig.proofs[t].input, msgs[t], params)
        else:
            Cv.hashes[t] = None

    missingLeavesSize = params.numMPCRounds - params.numOpenedRounds
    missingLeaves = getMissingLeavesList(sig.challengeC, params)
    ret = tree.addMerkleNodes(treeCv, missingLeaves, missingLeavesSize, sig.cvInfo, sig.cvInfoLen)
    # free(missingLeaves)
    if ret != 0:
        return -1

    ret = tree.verifyMerkleTree(treeCv, Cv.hashes, sig.salt, params)
    if ret != 0:
        return -1

    HCP(challengeHash, None, None, Ch, treeCv.nodes[0], sig.salt, pubKey, plaintext, message, messageByteLength, params)

    if sig.challengeHash != challengeHash:
        print("Challenge does not match, signature invalid")
        return -1

    ret = EXIT_SUCCESS

    picnic_types.freeCommitments(C)
    picnic_types.freeCommitments2(Cv)
    picnic_types.freeCommitments2(Ch)
    picnic_types.freeMsgs(msgs)
    picnic_types.freeTree(treeCv)
    picnic_types.freeTree(iSeedsTree)
    for t in range(params.numMPCRounds):
        picnic_types.freeRandomTape(tapes[t])
        picnic_types.freeTree(seeds[t])
    # free(seeds)
    # free(tapes)

    return ret


def computeSaltAndRootSeed(saltAndRoot, saltAndRootLength, privateKey, pubKey, plaintext, message, messageByteLength, params):
    ctx = HashInstance()
    
    HashInit(ctx, params, HASH_PREFIX_NONE)
    HashUpdate(ctx, bytes(privateKey), params.stateSizeBytes)
    HashUpdate(ctx, message, messageByteLength)
    HashUpdate(ctx, bytes(pubKey), params.stateSizeBytes)
    HashUpdate(ctx, bytes(plaintext), params.stateSizeBytes)
    HashUpdateIntLE(ctx, params.stateSizeBits)
    HashFinal(ctx)
    HashSqueeze(ctx, saltAndRoot, saltAndRootLength)

def sign_picnic3(privateKey, pubKey, plaintext, message, messageByteLength, sig, params):
    ret = 0
    treeCv = None
    Ch = commitments_t()
    Cv = commitments_t()
    saltAndRoot = bytearray(params.saltSizeBytes + params.seedSizeBytes)

    computeSaltAndRootSeed(saltAndRoot, params.saltSizeBytes + params.seedSizeBytes, privateKey, pubKey, plaintext, message, messageByteLength, params)
    sig.salt = saltAndRoot[:params.saltSizeBytes]
    iSeedsTree = tree.generateSeeds(params.numMPCRounds, saltAndRoot[params.saltSizeBytes:], sig.salt, 0, params)
    iSeeds = tree.getLeaves(iSeedsTree)
    del saltAndRoot

    tapes = [randomTape_t() for _ in range(params.numMPCRounds)]
    seeds = [None] * params.numMPCRounds
    for t in range(params.numMPCRounds):
        seeds[t] = tree.generateSeeds(params.numMPCParties, iSeeds[t], sig.salt, t, params)
        createRandomTapes(tapes[t], tree.getLeaves(seeds[t]), sig.salt, t, params)

    inputs = picnic_types.allocateInputs(params)
    auxBits = bytearray(MAX_AUX_BYTES)
    for t in range(params.numMPCRounds):
        computeAuxTape(tapes[t], inputs[t], params)

    C = allocateCommitments(params, 0)
    for t in range(params.numMPCRounds):
        for j in range(params.numMPCParties - 1):
            commit(C[t].hashes[j], tree.getLeaf(seeds[t], j), None, sig.salt, t, j, params)
        last = params.numMPCParties - 1
        getAuxBits(auxBits, tapes[t], params)
        commit(C[t].hashes[last], tree.getLeaf(seeds[t], last), auxBits, sig.salt, t, last, params)

    msgs = picnic_types.allocateMsgs(params)
    tmp_shares = picnic_types.allocateShares(params.stateSizeBits)
    for t in range(params.numMPCRounds):
        maskedKey = inputs[t]
        xor_array(maskedKey, maskedKey, privateKey, params.stateSizeWords)
        rv = simulateOnline(maskedKey, tapes[t], tmp_shares, msgs[t], plaintext, pubKey, params)
        if rv != 0:
            print(("MPC simulation failed, aborting signature\n"))
            picnic_types.freeShares(tmp_shares)
            ret = -1
            return ret
    picnic_types.freeShares(tmp_shares)

    picnic_types.allocateCommitments2(Ch, params, params.numMPCRounds)
    picnic_types.allocateCommitments2(Cv, params, params.numMPCRounds)
    for t in range(params.numMPCRounds):
        commit_h(Ch.hashes[t], C[t], params)
        commit_v(Cv.hashes[t], inputs[t], msgs[t], params)

    treeCv = tree.createTree(params.numMPCRounds, params.digestSizeBytes)
    tree.buildMerkleTree(treeCv, Cv.hashes, sig.salt, params)

    challengeC = sig.challengeC
    challengeP = sig.challengeP
    HCP(sig.challengeHash, challengeC, challengeP, Ch, treeCv.nodes[0], sig.salt, pubKey, plaintext, message, messageByteLength, params)

    missingLeavesSize = params.numMPCRounds - params.numOpenedRounds
    missingLeaves = getMissingLeavesList(challengeC, params)
    cvInfoLen = 0
    cvInfo = tree.openMerkleTree(treeCv, missingLeaves, missingLeavesSize, cvInfoLen)
    sig.cvInfo = cvInfo
    sig.cvInfoLen = cvInfoLen
    del missingLeaves

    sig.iSeedInfo = bytearray(params.numMPCRounds * params.seedSizeBytes)
    sig.iSeedInfoLen = tree.revealSeeds(iSeedsTree, challengeC, params.numOpenedRounds, sig.iSeedInfo, params.numMPCRounds * params.seedSizeBytes, params)
    sig.iSeedInfo = sig.iSeedInfo[:sig.iSeedInfoLen]

    proofs = [proof2_t() for _ in range(params.numMPCRounds)]
    for t in range(params.numMPCRounds):
        if t in challengeC:
            picnic_types.allocateProof2(proofs[t], params)
            P_index = challengeC.index(t)

            hideList = [challengeP[P_index]]
            proofs[t].seedInfo = bytearray(params.numMPCParties * params.seedSizeBytes)
            proofs[t].seedInfoLen = tree.revealSeeds(seeds[t], hideList, 1, proofs[t].seedInfo, params.numMPCParties * params.seedSizeBytes, params)
            proofs[t].seedInfo = proofs[t].seedInfo[:proofs[t].seedInfoLen]

            last = params.numMPCParties - 1
            if challengeP[P_index] != last:
                getAuxBits(proofs[t].aux, tapes[t], params)

            proofs[t].input = inputs[t][:]
            proofs[t].msgs = msgs[t].msgs[challengeP[P_index]][:]
            proofs[t].C = C[t].hashes[challengeP[P_index]][:]

    sig.proofs = proofs

    # Self-Test, try to verify signature
    # rv = verify_picnic3(sig, pubKey, plaintext, message, messageByteLength, params)
    # if rv != 0:
    #     print("Verification failed; signature invalid")
    #     ret = -1
    # else:
    #     print("Verification succeeded")

    for t in range(params.numMPCRounds):
        picnic_types.freeRandomTape(tapes[t])
        picnic_types.freeTree(seeds[t])
    del tapes
    del seeds
    picnic_types.freeTree(iSeedsTree)
    picnic_types.freeTree(treeCv)

    picnic_types.freeCommitments(C)
    picnic_types.freeCommitments2(Ch)
    picnic_types.freeCommitments2(Cv)
    picnic_types.freeInputs(inputs)
    picnic_types.freeMsgs(msgs)

    return ret



def deserializeSignature2(sig, sigBytes, sigBytesLen, params):
    # Read the challenge and salt
    bytesRequired = params.digestSizeBytes + params.saltSizeBytes

    if sigBytesLen < bytesRequired:
        return EXIT_FAILURE

    sig.challengeHash = sigBytes[:params.digestSizeBytes]
    sigBytes = sigBytes[params.digestSizeBytes:]
    sig.salt = sigBytes[:params.saltSizeBytes]
    sigBytes = sigBytes[params.saltSizeBytes:]

    expandChallengeHash(sig.challengeHash, sig.challengeC, sig.challengeP, params)

    # Add size of iSeeds tree data
    sig.iSeedInfoLen = tree.revealSeedsSize(params.numMPCRounds, sig.challengeC, params.numOpenedRounds, params)
    bytesRequired += sig.iSeedInfoLen

    # Add the size of the Cv Merkle tree data
    missingLeavesSize = params.numMPCRounds - params.numOpenedRounds
    missingLeaves = getMissingLeavesList(sig.challengeC, params)
    sig.cvInfoLen = tree.openMerkleTreeSize(params.numMPCRounds, missingLeaves, missingLeavesSize, params)
    bytesRequired += sig.cvInfoLen
    # free(missingLeaves)

    # Compute the number of bytes required for the proofs
    hideList = [0]
    seedInfoLen = tree.revealSeedsSize(params.numMPCParties, hideList, 1, params)
    for t in range(params.numMPCRounds):
        if contains(sig.challengeC, params.numOpenedRounds, t):
            P_t = sig.challengeP[indexOf(sig.challengeC, params.numOpenedRounds, t)]
            if P_t != (params.numMPCParties - 1):
                bytesRequired += params.andSizeBytes
            bytesRequired += seedInfoLen
            bytesRequired += params.stateSizeBytes
            bytesRequired += params.andSizeBytes
            bytesRequired += params.digestSizeBytes

    # Fail if the signature does not have the exact number of bytes we expect
    if sigBytesLen != bytesRequired:
        print(f"sigBytesLen = {sigBytesLen}, expected bytesRequired = {bytesRequired}")
        return EXIT_FAILURE

    sig.iSeedInfo = sigBytes[:sig.iSeedInfoLen]
    sigBytes = sigBytes[sig.iSeedInfoLen:]

    sig.cvInfo = sigBytes[:sig.cvInfoLen]
    sigBytes = sigBytes[sig.cvInfoLen:]

    # Read the proofs
    for t in range(params.numMPCRounds):
        if contains(sig.challengeC, params.numOpenedRounds, t):
            picnic_types.allocateProof2(sig.proofs[t], params)
            sig.proofs[t].seedInfoLen = seedInfoLen
            sig.proofs[t].seedInfo = sigBytes[:sig.proofs[t].seedInfoLen]
            sigBytes = sigBytes[sig.proofs[t].seedInfoLen:]

            P_t = sig.challengeP[indexOf(sig.challengeC, params.numOpenedRounds, t)]
            if P_t != (params.numMPCParties - 1):
                sig.proofs[t].aux = sigBytes[:params.andSizeBytes]
                sigBytes = sigBytes[params.andSizeBytes:]
                if not arePaddingBitsZero(sig.proofs[t].aux, 3 * params.numRounds * params.numSboxes):
                    print("failed while deserializing aux bits")
                    return -1

            sig.proofs[t].input = sigBytes[:params.stateSizeBytes]
            sigBytes = sigBytes[params.stateSizeBytes:]

            msgsByteLength = params.andSizeBytes
            sig.proofs[t].msgs = sigBytes[:msgsByteLength]
            sigBytes = sigBytes[msgsByteLength:]
            msgsBitLength = 3 * params.numRounds * params.numSboxes
            if not arePaddingBitsZero(sig.proofs[t].msgs, msgsBitLength):
                print("failed while deserializing msgs bits")
                return -1

            sig.proofs[t].C = sigBytes[:params.digestSizeBytes]
            sigBytes = sigBytes[params.digestSizeBytes:]

    return EXIT_SUCCESS


def serializeSignature2(sig, sigBytes, sigBytesLen, params):
    sigBytesBase = sigBytes

    # Compute the number of bytes required for the signature
    bytesRequired = params.digestSizeBytes + params.saltSizeBytes  # challenge and salt

    bytesRequired += sig.iSeedInfoLen  # Encode only iSeedInfo, the length will be recomputed by deserialize
    bytesRequired += sig.cvInfoLen

    for t in range(params.numMPCRounds):  # proofs
        if contains(sig.challengeC, params.numOpenedRounds, t):
            P_t = sig.challengeP[indexOf(sig.challengeC, params.numOpenedRounds, t)]
            bytesRequired += sig.proofs[t].seedInfoLen
            if P_t != (params.numMPCParties - 1):
                bytesRequired += params.andSizeBytes
            bytesRequired += params.stateSizeBytes
            bytesRequired += params.andSizeBytes
            bytesRequired += params.digestSizeBytes

    if sigBytesLen < bytesRequired:
        return -1

    sigBytes[:params.digestSizeBytes] = sig.challengeHash
    sigBytes += params.digestSizeBytes

    sigBytes[:params.saltSizeBytes] = sig.salt
    sigBytes += params.saltSizeBytes

    sigBytes[:sig.iSeedInfoLen] = sig.iSeedInfo
    sigBytes += sig.iSeedInfoLen
    sigBytes[:sig.cvInfoLen] = sig.cvInfo
    sigBytes += sig.cvInfoLen

    # Write the proofs
    for t in range(params.numMPCRounds):
        if contains(sig.challengeC, params.numOpenedRounds, t):
            sigBytes[:sig.proofs[t].seedInfoLen] = sig.proofs[t].seedInfo
            sigBytes += sig.proofs[t].seedInfoLen

            P_t = sig.challengeP[indexOf(sig.challengeC, params.numOpenedRounds, t)]

            if P_t != (params.numMPCParties - 1):
                sigBytes[:params.andSizeBytes] = sig.proofs[t].aux
                sigBytes += params.andSizeBytes

            sigBytes[:params.stateSizeBytes] = sig.proofs[t].input
            sigBytes += params.stateSizeBytes

            sigBytes[:params.andSizeBytes] = sig.proofs[t].msgs
            sigBytes += params.andSizeBytes

            sigBytes[:params.digestSizeBytes] = sig.proofs[t].C
            sigBytes += params.digestSizeBytes

    return int(sigBytes - sigBytesBase)


