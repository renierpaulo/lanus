"""Referencia independente BIP39/BIP32 -> gera vetores de teste para validar o CUDA."""
import hashlib, hmac, unicodedata

P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def pt_add(p, q):
    if p is None: return q
    if q is None: return p
    x1, y1 = p; x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if p == q:
        lam = 3 * x1 * x1 * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def pt_mul(k, p=(GX, GY)):
    r = None
    while k:
        if k & 1: r = pt_add(r, p)
        p = pt_add(p, p); k >>= 1
    return r


def ser_p(pt):
    x, y = pt
    return bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')


def ripemd160(b):
    try:
        return hashlib.new('ripemd160', b).digest()
    except Exception:
        return _rmd160_pure(b)


def _rmd160_pure(msg):
    rol = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xffffffff
    RL = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    RR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    SL = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    SR = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    KL = [0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e]
    KR = [0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000]
    F = [lambda x,y,z: x^y^z, lambda x,y,z:(x&y)|(~x&0xffffffff&z),
         lambda x,y,z:(x|(~y&0xffffffff))^z, lambda x,y,z:(x&z)|(y&(~z&0xffffffff)),
         lambda x,y,z: x^(y|(~z&0xffffffff))]
    ml = len(msg)
    msg = msg + b'\x80' + b'\x00' * ((55 - ml) % 64) + (ml * 8).to_bytes(8, 'little')
    h = [0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0]
    for off in range(0, len(msg), 64):
        X = [int.from_bytes(msg[off+i*4:off+i*4+4], 'little') for i in range(16)]
        al,bl,cl,dl,el = h; ar,br,cr,dr,er = h
        for j in range(80):
            rnd = j // 16
            t = (rol((al + F[rnd](bl,cl,dl) + X[RL[j]] + KL[rnd]) & 0xffffffff, SL[j]) + el) & 0xffffffff
            al,el,dl,cl,bl = el,dl,rol(cl,10),bl,t
            t = (rol((ar + F[4-rnd](br,cr,dr) + X[RR[j]] + KR[rnd]) & 0xffffffff, SR[j]) + er) & 0xffffffff
            ar,er,dr,cr,br = er,dr,rol(cr,10),br,t
        h = [(h[1]+cl+dr) & 0xffffffff, (h[2]+dl+er) & 0xffffffff, (h[3]+el+ar) & 0xffffffff,
             (h[4]+al+br) & 0xffffffff, (h[0]+bl+cr) & 0xffffffff]
    return b''.join(x.to_bytes(4, 'little') for x in h)


def b58check(payload):
    A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(payload + chk, 'big')
    out = ''
    while n:
        n, r = divmod(n, 58); out = A[r] + out
    return '1' * (len(payload + chk) - len((payload + chk).lstrip(b'\x00'))) + out


def derive(mnemonic, path=(("44'",), ("0'",), ("0'",), ("0",), ("0",))):
    seed = hashlib.pbkdf2_hmac('sha512',
                               unicodedata.normalize('NFKD', mnemonic).encode(),
                               b'mnemonic', 2048)
    I = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    k, cc = int.from_bytes(I[:32], 'big'), I[32:]
    for (lvl,) in path:
        hard = lvl.endswith("'")
        idx = int(lvl.rstrip("'")) + (0x80000000 if hard else 0)
        data = (b'\x00' + k.to_bytes(32, 'big') if hard else ser_p(pt_mul(k))) + idx.to_bytes(4, 'big')
        I = hmac.new(cc, data, hashlib.sha512).digest()
        k = (int.from_bytes(I[:32], 'big') + k) % N
        cc = I[32:]
    pub = ser_p(pt_mul(k))
    h160 = ripemd160(hashlib.sha256(pub).digest())
    return seed, k, pub, h160, b58check(b'\x00' + h160)


if __name__ == '__main__':
    for m in ["galaxy man boy evil donkey child cross chair egg meat blood space",
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"]:
        seed, k, pub, h160, addr = derive(m)
        print(f"--- {m[:52]}...")
        print(f"  seed    {seed.hex()}")
        print(f"  privkey {k:064x}")
        print(f"  pubkey  {pub.hex()}")
        print(f"  hash160 {h160.hex()}")
        print(f"  address {addr}")
