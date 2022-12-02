#!/usr/bin/env python3

import collections
import random
import hashlib
import hmac
import binascii
import hkdf
from Crypto.Cipher import AES
from Crypto import Random
import base64

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


# Modular arithmetic ##########################################################

def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


# Keypair generation and ECDHE ################################################

def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key

def Install():
    private_key_I = random.randrange(1, curve.n)
    public_key_I = scalar_mult(private_key_I, curve.g)

    private_key_S = random.randrange(1, curve.n)
    public_key_S = scalar_mult(private_key_S, curve.g)

    private_key_O = random.randrange(1, curve.n)
    public_key_O = scalar_mult(private_key_O, curve.g)

    private_key_D = random.randrange(1, curve.n)
    public_key_D = scalar_mult(private_key_D, curve.g)

    return private_key_I, private_key_S, private_key_O, private_key_D, public_key_I, public_key_S, public_key_O, public_key_D



BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]




def encrypt(raw, password):
    raw = str(raw)
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw.encode()))


def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))






print('Curve:', curve.name)

# Alice generates her own keypair.
alice_private_key_I, alice_private_key_S, alice_private_key_O, alice_private_key_D, alice_public_key_I, alice_public_key_S, alice_public_key_O, alice_public_key_D = Install()
alice_private_key_E, alice_public_key_E = make_keypair()
print("Alice's private keys I:", hex(alice_private_key_I))
print("Alice's private keys S:", hex(alice_private_key_S))
print("Alice's private keys O:", hex(alice_private_key_O))
print("Alice's private key:", hex(alice_private_key_E))
print("Alice's public key: (0x{:x}, 0x{:x})".format(*alice_public_key_E))
print('')


# Bob generates his own key pair.
bob_private_key_I, bob_private_key_S, bob_private_key_O, bob_private_key_D,  bob_public_key_I, bob_public_key_S, bob_public_key_O, bob_public_key_D  = Install()
bob_private_key_E, bob_public_key_E = make_keypair()
print("Bob's private keys I:", hex(bob_private_key_I))
print("Bob's private keys S:", hex(bob_private_key_S))
print("Bob's private keys O:", hex(bob_private_key_O))
print("Bob's private key:", hex(bob_private_key_E))
print("Bob's public key: (0x{:x}, 0x{:x})".format(*bob_public_key_E))
print('')
# Alice and Bob exchange their public keys and calculate the shared secret.
bob_s1 = scalar_mult(bob_private_key_I, alice_public_key_S)
bob_s2 = scalar_mult(bob_private_key_E, alice_public_key_I)
bob_s3 = scalar_mult(bob_private_key_E, alice_public_key_S)
bob_s4 = scalar_mult(bob_private_key_E, alice_public_key_O)



bob_master_X = (bob_s1[0] | bob_s2[0]) | (bob_s3[0] | bob_s4[0])
bob_master_Y = (bob_s1[1] | bob_s2[1]) | (bob_s3[1] | bob_s4[1])

alice_s1 = scalar_mult(alice_private_key_S, bob_public_key_I)
alice_s2 = scalar_mult(alice_private_key_I, bob_public_key_E)
alice_s3 = scalar_mult(alice_private_key_S, bob_public_key_E)
alice_s4 = scalar_mult(alice_private_key_O, bob_public_key_E)

alice_master_X = (alice_s1[0] | alice_s2[0]) | (alice_s3[0] | alice_s4[0])
alice_master_Y = (alice_s1[1] | alice_s2[1]) | (alice_s3[1] | alice_s4[1])
assert ((bob_master_X == alice_master_X) and (bob_master_Y == alice_master_Y))

print('Master key X:',bob_master_X )
print('Master key Y:',bob_master_Y )
print('')

#=======================================================================================================================

#dimiourgia tou R0 root key
master = bob_master_X + bob_master_Y




prk = hkdf.hkdf_extract(binascii.unhexlify(b""), str(master).encode())
key = hkdf.hkdf_expand(prk, b"", 32)
R0 = int.from_bytes(key, "big")
print ("Root key from master with hkdf as int:",R0)

print('')
#=======================================================================================================================

bob_D0 = scalar_mult(bob_private_key_D, alice_public_key_D)
alice_D0 = scalar_mult(alice_private_key_D, bob_public_key_D)

D0 = bob_D0[0] + bob_D0[1]
alice_D0_final = alice_D0[0] + alice_D0[1]
assert (D0 == alice_D0_final)

print('Shared secret key for the first key of the key chain as int:...',D0 )


prk = hkdf.hkdf_extract(binascii.unhexlify(b""), str(R0).encode())
key = hkdf.hkdf_expand(prk, b"", 32)
C1 = int.from_bytes(key, "big")

prk = hkdf.hkdf_extract(binascii.unhexlify(b""), str(D0).encode())
key = hkdf.hkdf_expand(prk, b"", 32)
R1 = int.from_bytes(key, "big")
print('')
print('')
#=======================================================================================================================
m = hmac.new(str(C1).encode(), digestmod=hashlib.sha256)
m.update(b'0x01')

C2 = hmac.new(str(C1).encode(), digestmod=hashlib.sha256)
C2.update(b'0x02')
print("The message key is M=",m.hexdigest())
print("Second key of key chain for the next message is C2=",C2.hexdigest())
print('')
print('')
#=======================================================================================================================

password = m.hexdigest()
message = input ("what do you want to say:...")
# First let us encrypt secret message
encrypted = encrypt(message, password)
print("The encrypted message is:...",encrypted)
print('')
print('')

signed = hmac.new(str(m).encode(), digestmod=hashlib.sha256)
m.update(message.encode())

print("And the signed massage is:...",signed.hexdigest())

# Let us decrypt using our original password
decrypted = decrypt(encrypted, password)
print(bytes.decode(decrypted))
