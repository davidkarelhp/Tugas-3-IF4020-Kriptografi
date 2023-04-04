import copy

def stringToBit(m):
    con = ''.join(format(ord(x), '08b') for x in m)
    res = ''
    for i in range(0, len(con), 8):
        res += con[i:i+8][::-1]
    return res

def bitToHex(m):
    res = ''
    for i in range(0, len(m), 8):
        res += m[i:i+8][::-1]
    return hex(int(res, 2))

def hexToBit(m):
    scale = 16
    num_of_bits = 8
    return bin(int(m, scale))[2:].zfill(num_of_bits)

def hexToBitFull(m):
    res = ''
    for i in range(0, len(m), 2):
        res += hexToBit(m[i:i+2])
    return res[::-1]

def convertToString(array):
    res = ''
    for i in reversed(range(5)):
        for j in reversed(range(5)):
            res += array[i][j]
    return res

def xor(x, y):
    res = ''
    for i in range(len(x)):
        if x[i] == y[i]:
            res += '0'
        else:
            res += '1'
    return res

def negate(x):
    res = ''
    for i in range(len(x)):
        if x[i] == '0':
            res += '1'
        else:
            res += '0'
    return res

def andOp(x, y):
    res = ''
    for i in range(len(x)):
        if x[i] == '1' and y[i] == '1':
            res += '1'
        else:
            res += '0'
    return res

def padMessage(bit, r):
    bit += '1'
    while len(bit) % r != r-1:
        bit += '0'
    bit += '1'
    return bit

def splitToBlock(bit, r):
    block = []
    for i in range(0,len(bit),r):
        block.append(bit[i:i+r])
    return block

def getB(x):
    b = ''
    for i in range(x):
        b += '0'
    return b

def getState(block):
    state = [[ '' for i in range(5)] for j in range(5)]
    blok = splitToBlock(block, 64)
    for i in range(5):
        for j in range(5):
            state[i][j] = blok[i*5+j]
    return state

def rot(W,r):
    resArr = ['' for i in range(len(W))]
    res = ''
    for i in range(len(W)):
        newPos = (i+r) % len(W)
        resArr[newPos] = W[i]
    for x in resArr:
        res += x
    return res

def RC(t):
    res = [
        '0000000000000001', 
        '0000000000008082', 
        '800000000000808a', 
        '8000000080008000', 
        '000000000000808b', 
        '0000000080000001', 
        '8000000080008081', 
        '8000000000008009', 
        '000000000000008a', 
        '0000000000000088', 
        '0000000080008009', 
        '000000008000000a', 
        '000000008000808b', 
        '800000000000008b', 
        '8000000000008089', 
        '8000000000008003', 
        '8000000000008002', 
        '8000000000000080', 
        '000000000000800a', 
        '800000008000000a', 
        '8000000080008081', 
        '8000000000008080', 
        '0000000080000001',
        '8000000080008008'
    ]
    return hexToBitFull(res[t])

def r(i, j):
    res = [
        [0, 36, 3, 41, 48],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]
    return res[i][j]

def theta(state):
    c = ['' for i in range(5)]
    d = ['' for i in range(5)]
    res = copy.deepcopy(state)
    for i in range(5):
        c[i] = xor(state[i][0], xor(state[i][1], xor(state[i][2], xor(state[i][3], state[i][4]))))
    for i in range(5):
        d[i] = xor(c[(i-1) % 5], rot(c[(i+1) % 5], 1))
    for i in range(5):
        for j in range(5):
            res[i][j] = xor(state[i][j], d[i])
    return res

def rho(state):
    res = copy.deepcopy(state)
    i = 1
    j = 0
    for t in range(24):
        res[i][j] = rot(state[i][j],int((t+1)*(t+2)/2))
        newI = ((i * 0) + (1 * j)) % 5
        newJ = ((i * 2) + (3 * j)) % 5
        i = newI
        j = newJ
    return res

def pi(state):
    res = copy.deepcopy(state)
    for i in range(5):
        for j in range(5):
            res[j][(2*i + 3*j)%5] = state[i][j]
            # res[j][(2*i + 3*j)%5] = rot(state[i][j], r(i,j))
            # # res[j][(2*i + 3*j)%5] = rot(state[i][j], RC(i+5*j))
            # print(i+5*j)
            # print(RC(24))
            # # print(RC(i+5*j))
    return res

def chi(state):
    res = copy.deepcopy(state)
    for i in range(5):
        for j in range(5):
            res[i][j] = xor(state[i][j], andOp(negate(state[(i+1)%5 ][j]), state[(i+2)%5 ][j]))
    return res

def iota(state, t):
    state[0][0] = xor(state[0][0], RC(t))
    return state

def permutation(block):
    state = getState(block)
    for i in range(24):
        # theta
        state = theta(state)
        # rho
        state = rho(state)
        # pi
        state = pi(state)
        # chi
        state = chi(state)
        # iota
        state = iota(state, i)
    return convertToString(state)

def absorb(block, r, c):
    # initialize the state S to a string of b zero bits
    b = getB(r+c)
    cBit = getB(c)

    for i in block:
        i += cBit
        b = xor(i,b)
        b = permutation(b)
    return b

def squeeze(serap, r, d):
    Z = ''
    while len(Z) < d:
        Z += serap[:r]
        serap = permutation(serap)
    return Z[:d]

# message, capacity, rate, output
def keccak(m, c, r, d):
    bit = stringToBit(m)

    # pad the input N using the pad function
    if len(bit) % r != 0:
        bit = padMessage(bit, r)

    # break P into n consecutive r-bit pieces
    block = splitToBlock(bit, r)

    #absorb the input into the state:
    serap = absorb(block, r, c)
    peras = squeeze(serap, r, d)
    return bitToHex(peras)

if __name__ == "__main__":
    x = keccak("OK",512,1088,256)
    # x = keccak("helloworld",512,1088,256)
    print(x)

# 565339bc4d33d72817b583024112eb7f5cdf3e5eef0252d6ec1b9c9a94e12bb3
# 40346dd904de4c9cf4ca6bdc73a90803011ac2fb8609da6125f700999664bc6d


#OK
#daa4f5d475c02455977059e29f0bd4c2f7e92e8cfa8026b3dcd2c374e8a520e6