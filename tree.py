import math
import numpy as np
from picnic_types import *
from hash import *
from picnic import *
from picnic_impl import *
import sys

class tree_t:
    def __init__(self, depth, data_size):
        self.depth = depth       # The depth of the tree
        self.nodes = [None] * (2 ** (depth + 1) - 1)  # The data for each node
        self.data_size = data_size  # The size data at each node, in bytes
        self.have_node = [0] * (2 ** (depth + 1) - 1)  # If we have the data (seed or hash) for node i, haveSeed[i] is 1
        self.exists = [1] * (2 ** (depth + 1) - 1)  # Since the tree is not always complete, nodes marked 0 don't exist
        self.num_nodes = 2 ** (depth + 1) - 1  # The total number of nodes in the tree
        self.num_leaves = 2 ** depth  # The total number of leaves in the tree

# The largest seed size is 256 bits, for the Picnic3-L5-FS parameter set.
MAX_SEED_SIZE_BYTES = 32
INT_MAX = sys.maxsize

MAX_DIGEST_SIZE = 64


def printHex(s, data):
    print(f"{s}: ", end="")
    for byte in data:
        print(f"{byte:02X}", end="")
    print()

def contains(lst, value):
    return value in lst

def exists(tree, i):
    if i >= tree.numNodes:
        return False
    return tree.exists[i]

class tree_t:
    pass

def createTree(numLeaves, dataSize):
    tree = tree_t()
    tree.depth = math.ceil(math.log2(numLeaves)) + 1
    tree.numNodes = ((1 << tree.depth) - 1) - ((1 << (tree.depth - 1)) - numLeaves)
    tree.numLeaves = numLeaves
    tree.dataSize = dataSize
    tree.nodes = [bytearray(dataSize) for _ in range(tree.numNodes)]
    tree.haveNode = [False] * tree.numNodes
    tree.exists = [False] * tree.numNodes
    tree.exists[-tree.numLeaves:] = [True] * tree.numLeaves

    for i in range(tree.numNodes - tree.numLeaves, 0, -1):
        if exists(tree, 2 * i + 1) or exists(tree, 2 * i + 2):
            tree.exists[i] = True
    tree.exists[0] = True

    return tree

def freeTree(tree):
    if tree:
        del tree.nodes[0]
        del tree.nodes
        del tree.haveNode
        del tree.exists

def isLeftChild(node):
    assert node != 0
    return node % 2 == 1

def hasRightChild(tree, node):
    return 2 * node + 2 < tree.numNodes and exists(tree, node)

def hasLeftChild(tree, node):
    return 2 * node + 1 < tree.numNodes

def getParent(node):
    assert node != 0
    if isLeftChild(node):
        return (node - 1) // 2
    return (node - 2) // 2

def getLeaves(tree):
    return tree.nodes[tree.numNodes - tree.numLeaves:]

def getLeaf(tree, leafIndex):
    assert leafIndex < tree.numLeaves
    firstLeaf = tree.numNodes - tree.numLeaves
    return tree.nodes[firstLeaf + leafIndex]

def hashSeed(digest, inputSeed, salt, hashPrefix, repIndex, nodeIndex):
    ctx = HashInstance()
    ctx.ctx.update(inputSeed)
    ctx.ctx.update(salt)
    ctx.ctx.update(repIndex.to_bytes(2, 'little'))
    ctx.ctx.update(nodeIndex.to_bytes(2, 'little'))
    digest[:] = ctx.ctx.digest()

def expandSeeds(tree, salt, repIndex):
    tmp = bytearray(2 * MAX_DIGEST_SIZE)

    lastNonLeaf = getParent(tree.numNodes - 1)
    for i in range(lastNonLeaf + 1):
        if not tree.haveNode[i]:
            continue

        hashSeed(tmp, tree.nodes[i], salt, HASH_PREFIX_1, repIndex, i)

        if not tree.haveNode[2 * i + 1]:
            tree.nodes[2 * i + 1][:] = tmp[:tree.dataSize]
            tree.haveNode[2 * i + 1] = True

        if exists(tree, 2 * i + 2) and not tree.haveNode[2 * i + 2]:
            tree.nodes[2 * i + 2][:] = tmp[tree.dataSize:]
            tree.haveNode[2 * i + 2] = True

def generateSeeds(nSeeds, rootSeed, salt, repIndex):
    tree = createTree(nSeeds, len(rootSeed))
    tree.nodes[0][:] = rootSeed
    tree.haveNode[0] = True
    expandSeeds(tree, salt, repIndex)
    return tree

def isLeafNode(tree, node):
    return 2 * node + 1 >= tree.numNodes

def hasSibling(tree, node):
    if not exists(tree, node):
        return False

    if isLeftChild(node) and not exists(tree, node + 1):
        return False

    return True

def getSibling(tree, node):
    assert node < tree.numNodes
    assert node != 0
    assert hasSibling(tree, node)

    if isLeftChild(node):
        if node + 1 < tree.numNodes:
            return node + 1
        else:
            assert False, "getSibling: request for node with not sibling"
    else:
        return node - 1

def printSeeds(seedsBuf, seedLen, numSeeds):
    for i in range(numSeeds):
        print("seed", i, end="")
        printHex("", seedsBuf[:seedLen])
        seedsBuf = seedsBuf[seedLen:]

def printLeaves(tree):
    firstLeaf = tree.numNodes - tree.numLeaves
    printSeeds(tree.nodes[firstLeaf], tree.dataSize, tree.numLeaves)

def getRevealedNodes(tree, hideList, hideListSize):
    pathLen = tree.depth - 1
    pathSets = [[0] * hideListSize for _ in range(pathLen)]

    for i in range(hideListSize):
        pos = 0
        node = hideList[i] + (tree.numNodes - tree.numLeaves)
        pathSets[pos][i] = node
        pos += 1
        while (node := getParent(node)) != 0:
            pathSets[pos][i] = node
            pos += 1

    revealed = []
    for d in range(pathLen):
        for i in range(hideListSize):
            if not hasSibling(tree, pathSets[d][i]):
                continue
            sibling = getSibling(tree, pathSets[d][i])
            if sibling not in pathSets[d]:
                while not hasRightChild(tree, sibling) and not isLeafNode(tree, sibling):
                    sibling = 2 * sibling + 1
                if sibling not in revealed:
                    revealed.append(sibling)

    return revealed

def revealSeedsSize(numNodes, hideList, hideListSize, params):
    tree = createTree(numNodes, params.seedSizeBytes)
    numNodesRevealed = 0
    revealed = getRevealedNodes(tree, hideList, hideListSize, numNodesRevealed)

    freeTree(tree)
    # free(revealed)
    return numNodesRevealed * params.seedSizeBytes


def revealSeeds(tree, hideList, hideListSize, output, outputSize):
    outputBase = output

    revealed = getRevealedNodes(tree, hideList, hideListSize)
    for node in revealed:
        outputSize -= tree.dataSize
        if outputSize < 0:
            assert False, "Insufficient sized buffer provided to revealSeeds"
        output[:tree.dataSize] = tree.nodes[node]
        output = output[tree.dataSize:]

    return output - outputBase


def reconstructSeeds(tree, hideList, hideListSize, input, inputLen, salt, repIndex, params):
    ret = 0

    if inputLen > INT_MAX:
        return -1
    inLen = inputLen

    revealedSize = 0
    revealed = getRevealedNodes(tree, hideList, hideListSize, revealedSize)
    for i in range(revealedSize):
        inLen -= params.seedSizeBytes
        if inLen < 0:
            ret = -1
            break
        tree.nodes[revealed[i]] = input
        tree.haveNode[revealed[i]] = 1
        input += params.seedSizeBytes

    expandSeeds(tree, salt, repIndex, params)

    # free(revealed)
    return ret

def computeParentHash(tree, child, salt, params):
    if not exists(tree, child):
        return

    parent = getParent(child)

    if tree.haveNode[parent]:
        return

    if not tree.haveNode[2 * parent + 1]:
        return

    if exists(tree, 2 * parent + 2) and not tree.haveNode[2 * parent + 2]:
        return

    ctx = HashInstance()

    HashInit(ctx, params, HASH_PREFIX_3)
    HashUpdate(ctx, tree.nodes[2 * parent + 1], params.digestSizeBytes)
    if hasRightChild(tree, parent):
        HashUpdate(ctx, tree.nodes[2 * parent + 2], params.digestSizeBytes)

    HashUpdate(ctx, salt, params.saltSizeBytes)
    HashUpdateIntLE(ctx, parent)
    HashFinal(ctx)
    HashSqueeze(ctx, tree.nodes[parent], params.digestSizeBytes)
    tree.haveNode[parent] = 1

def buildMerkleTree(tree, leafData, salt, params):
    firstLeaf = tree.numNodes - tree.numLeaves

    for i in range(tree.numLeaves):
        if leafData[i] is not None:
            tree.nodes[firstLeaf + i] = leafData[i]
            tree.haveNode[firstLeaf + i] = 1

    for i in range(tree.numNodes, 0, -1):
        computeParentHash(tree, i, salt, params)

def getRevealedMerkleNodes(tree, missingLeaves, missingLeavesSize, outputSize):
    firstLeaf = tree.numNodes - tree.numLeaves
    missingNodes = [0] * tree.numNodes

    for i in range(missingLeavesSize):
        missingNodes[firstLeaf + missingLeaves[i]] = 1

    lastNonLeaf = getParent(tree.numNodes - 1)
    for i in range(lastNonLeaf, 0, -1):
        if not exists(tree, i):
            continue
        if exists(tree, 2 * i + 2):
            if missingNodes[2 * i + 1] and missingNodes[2 * i + 2]:
                missingNodes[i] = 1
        else:
            if missingNodes[2 * i + 1]:
                missingNodes[i] = 1

    revealed = []
    for i in range(missingLeavesSize):
        node = missingLeaves[i] + firstLeaf
        while node != 0:
            if not missingNodes[getParent(node)]:
                if node not in revealed:
                    revealed.append(node)
                break
            node = getParent(node)

    outputSize = len(revealed)
    return revealed

def openMerkleTreeSize(numNodes, missingLeaves, missingLeavesSize, params):
    tree = createTree(numNodes, params.digestSizeBytes)
    revealedSize = 0
    revealed = getRevealedMerkleNodes(tree, missingLeaves, missingLeavesSize, revealedSize)

    freeTree(tree)
    # free(revealed)

    return revealedSize * params.digestSizeBytes

def openMerkleTree(tree, missingLeaves, missingLeavesSize, outputSizeBytes):
    revealedSize = 0
    revealed = getRevealedMerkleNodes(tree, missingLeaves, missingLeavesSize, revealedSize)

    outputSizeBytes = revealedSize * tree.dataSize
    output = []
    outputBase = output

    for i in range(revealedSize):
        output.append(tree.nodes[revealed[i]])

    # free(revealed)

    return outputBase

def addMerkleNodes(tree, missingLeaves, missingLeavesSize, input, inputSize):
    ret = 0

    assert missingLeavesSize < tree.numLeaves

    if inputSize > INT_MAX:
        return -1
    intLen = inputSize

    revealedSize = 0
    revealed = getRevealedMerkleNodes(tree, missingLeaves, missingLeavesSize, revealedSize)
    assert 0 not in revealed

    for i in range(revealedSize):
        intLen -= tree.dataSize
        if intLen < 0:
            ret = -1
            break
        tree.nodes[revealed[i]] = input
        input += tree.dataSize
        tree.haveNode[revealed[i]] = 1

    if intLen != 0:
        ret = -1

    # free(revealed)

    return ret

def verifyMerkleTree(tree, leafData, salt, params):
    firstLeaf = tree.numNodes - tree.numLeaves

    # Copy the leaf data, where we have it. The actual data being committed to has already been
    # hashed, according to the spec.
    for i in range(tree.numLeaves):
        if leafData[i] is not None:
            if tree.haveNode[firstLeaf + i] == 1:
                return -1  # A leaf was assigned from the prover for a node we've recomputed

            if leafData[i] is not None:
                tree.nodes[firstLeaf + i][:] = leafData[i]
                tree.haveNode[firstLeaf + i] = 1

    # At this point the tree has some of the leaves, and some intermediate nodes
    # Work up the tree, computing all nodes we don't have that are missing.
    for i in range(tree.numNodes, 0, -1):
        computeParentHash(tree, i, salt, params)

    # Fail if the root was not computed.
    if not tree.haveNode[0]:
        return -1

    return 0

