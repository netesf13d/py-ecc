# -*- coding: utf-8 -*-
"""
Implementation of Elliptic Curve Digital Signature Algorithm (ECDSA) from
RFC 6979 https://www.rfc-editor.org/rfc/rfc6979


"""

from collections.abc import Generator
from hashlib import (md5, sha1, sha224, sha256, sha384, sha512,
                     sha3_224, sha3_256, sha3_384, sha3_512)
from hmac import digest as hmac_digest
from typing import TypeAlias

from ..elliptic_curves.ec import (CurvePoint, Elliptic_Curve,
                                  get_curve, sqrt_mod)


HASHES = {'md5': md5, 'sha1': sha1, 'sha224': sha224,
          'sha256': sha256, 'sha384': sha384, 'sha512': sha512,
          'sha3-224': sha3_224, 'sha3-256': sha3_256,
          'sha3-384': sha3_384, 'sha3-512': sha3_512}

Signature: TypeAlias = tuple[int, int]

# =============================================================================
# utils
# =============================================================================

def bits2int(x: bytes, nbits: int)-> int:
    """
    Bit string to integers as per RFC 6979 section 2.3.2.
    """
    xlen = 8*len(x)
    x = int.from_bytes(x, byteorder='big')
    return x >> max(xlen - nbits, 0)


# def HMAC(msg: bytes, key: bytes, digestmod: Callable)-> bytes:
#     """
#     HMAC primitive for ECDSA key generation.
#     """
#     blen = digestmod().block_size
#     digest = lambda x: digestmod(x).digest()
#     # keys longer than digest length are hashed first
#     if len(key) > blen:
#         key = digest(key)
#     key = key + b'\x00' * (blen - len(key))
#     k = int.from_bytes(key, 'big')
#     ipad, opad = b'\x36'*blen, b'\x5c'*blen
#     kin = (k ^ int.from_bytes(ipad, 'big')).to_bytes(blen, 'big')
#     kout = (k ^ int.from_bytes(opad, 'big')).to_bytes(blen, 'big')
#     return digest(kout + digest(kin + msg))


# =============================================================================
# Elliptic Curve Digital Signature Algorithm Base class
# =============================================================================

class ECDSA_Base():

    def __init__(self,
                 elliptic_curve: Elliptic_Curve,
                 G: CurvePoint,
                 n: int,
                 hash_name: str = "sha256"):
        """
        Create an ECDSA instance with custom parameters.

        Parameters
        ----------
        elliptic_curve : Elliptic_Curve
            The elliptic curve.
        G : CurvePoint
            A subgroup generator.
        n : int
            The subgroup order Card(<G>).
        hash_name : str
            The name of the digest to use in the ECDSA instance. Involved in
            nonce generation and signature.
            The default is "sha256".
        """
        self.ec = elliptic_curve
        self.G = G
        self.n = n
        self.nbits = self.n.bit_length()
        self.nbytes = (self.nbits // 8) + (self.nbits % 8 > 0)

        self.hash_name = None
        self.digest = None
        self.digest_size = None
        self.hash_block_size = None
        self.set_digest(hash_name)


    def set_digest(self, hash_name: str):
        """
        Set another digest to use for ECDSA.
        """
        try:
            hash_obj = HASHES[hash_name.lower()]
        except KeyError:
            msg = f"available hashes are {set(HASHES.keys())}"
            raise ValueError(f"incorrect hash name {hash_name}, " + msg)
        self.hash_name = hash_name.lower()
        self.digest = lambda m: hash_obj(m).digest()
        self.digest_size = hash_obj().digest_size
        self.hash_block_size = hash_obj().block_size


    def msg2int(self, msg: bytes)-> int:
        """
        Digest message and convert to integer.
        The name echoes the `bits2int` function.
        """
        return bits2int(self.digest(msg), self.nbits) % self.n


    def nonce_gen(self, msg: bytes, sk: int)-> Generator[int, None, None]:
        """
        Deterministic nonce generator for ECDSA (see RFC 6979 section 3.2).
        Implemented as a generator in the (very unlikely) case k.G has a
        vanishing x-coordinate.
        """
        h = self.msg2int(msg)
        h = h.to_bytes(self.nbytes, byteorder='big')
        sk = sk.to_bytes(self.nbytes, byteorder='big')
        ## K/V initialization
        V = b'\x01' * self.digest_size # 3.2.b
        K = b'\x00' * self.digest_size # 3.2.c
        K = hmac_digest(K, V + b'\x00' + sk + h, self.hash_name) # 3.2.d
        V = hmac_digest(K, V, self.hash_name) # 3.2.e
        K = hmac_digest(K, V + b'\x01' + sk + h, self.hash_name) # 3.2.f
        V = hmac_digest(K, V, self.hash_name) # 3.2.g
        ## Final loop
        while True:
            T = b''
            while len(T) < self.nbytes:
                V = hmac_digest(K, V, self.hash_name)
                T += V
            k = bits2int(T, self.nbits)
            if k < self.n:
                yield k
            K = hmac_digest(K, V + b'\x00', self.hash_name)
            V = hmac_digest(K, V, self.hash_name)


    def sign(self,
             msg: bytes,
             sk: int,
             nonce: int | None = None)-> Signature:
        """
        Sign a message with ECDSA.

        The signature takes as inputs the message `msg` (bytes), the secret key
        `sk` (int), an optional nonce k and returns a pair of integers (r, s)
          r = the x-coordinate of k.G (mod n)
          s = (digest(msg) + r*sk) * k^(-1) (mod n)
        with n the order of <G>.

        If the nonce is not specified, the function defaults to the
        deterministic generation described in RFC 6979 section 3.2.
        """
        h = self.msg2int(msg)
        # nonce was provided manually -> raises ValueError if unsuitable
        if nonce is not None:
            r = self.ec.mult(self.G, nonce)[0] % self.n
            s = pow(nonce, -1, self.n) * (h + r*sk) % self.n
            if r == 0 or s == 0:
                raise ValueError("unsuitable nonce")
        # nonce not provided -> keep looping generation if unsuitable
        else:
            kgen = self.nonce_gen(msg, sk)
            r, s = 0, 0
            while r == 0 or s == 0:
                k = next(kgen)
                r = self.ec.mult(self.G, k)[0] % self.n
                s = pow(k, -1, self.n) * (h + r*sk) % self.n
        return (r, s)


    def verify(self, msg: bytes, sig: Signature, pk: CurvePoint)-> bool:
        """
        Verify the ECDSA signature (r, s) of a message `msg` associated to
        public key `pk`.

        With
          r = k.G[0] (mod n)
          s = k^(-1) * (h + r*sk) (mod n)
        Compute h from the message, then the verification is
          (s^(-1)*k.G + s^(-1)*r.pk)[0] (mod n) = r
        """
        # check the public key
        self.ec.check_points(pk)
        if pk == self.ec.identity:
            raise ValueError("public key set as the identity")
        if not self.ec.mult(pk, self.n) == self.ec.identity:
            raise ValueError("public_key not in the form sk.G")
        # check the signature pair
        r, s = sig
        if r == 0 or r >= self.n or s == 0 or s >= self.n:
            return False
        #
        h = self.msg2int(msg)
        u, v = h*pow(s, -1, self.n) % self.n, r*pow(s, -1, self.n) % self.n
        P = self.ec.add(self.ec.mult(self.G, u), self.ec.mult(pk, v))
        if P == self.ec.identity:
            return False
        if r == P[0] % self.n:
            return True
        return False


    def public_key(self, sk: int)-> bytes:
        """
        Public key from the secret sk.
        """
        return self.ec.mult(self.G, sk)


    def public_key_recovery(self,
                            msg: bytes,
                            sig: Signature)-> set[CurvePoint]:
        """
        Public key recovery from an ECDSA signature.

        From the value r = k.G[0] (mod n), reconstruct candidates points
        kG = (x, y(x)) = (r + i*n, y(r + i*n))
        Then we have the candidate public keys
        pk = r^(-1)*s.(x, y) - r^(-1)*h.G
        """
        ec = self.ec
        # check the signature pair
        r, s = sig
        if r == 0 or r >= self.n or s == 0 or s >= self.n:
            raise ValueError("invalid signature")
        #
        h = self.msg2int(msg)
        public_keys = set()
        for i in range((ec.p - r)//self.n + 1):
            rx = r + i*self.n
            ry = sqrt_mod(ec.eq_components((rx, 0))[1], ec.p)
            u = (-h * pow(r, -1, self.n)) % self.n
            v = (-s * pow(r, -1, self.n)) % self.n
            P1 = ec.add(ec.mult(self.G, u), ec.mult((rx, ry), v))
            P2 = ec.add(ec.mult(self.G, u), ec.mult((rx, ec.p - ry), v))
            public_keys |= {P1, P2}
        return public_keys


    def secret_recovery(self,
                        msg1: bytes, sig1: Signature,
                        msg2: bytes, sig2: Signature)-> tuple[int, int]:
        """
        Recover the secret key and nonce used from a pair of signatures with
        nonce reuse.

        We have, for shared nonce k, secret key sk, and distinct (but known)
        messages hashes h1 and h2:
          r1 = r2 = r = k.G[0] (mod n)
          s1 = k^(-1) * (h1 + r*sk) (mod n)
          s2 = k^(-1) * (h2 + r*sk) (mod n)
        hence
          s2 - s1 = k^(-1) * (h2 - h1) (mod n)
          k = (h2 - h1) / (s2 - s1) (mod n)
          sk = r^(-1) * (k*s1 - h1) (mod n)
        """
        r1, s1 = sig1
        r2, s2 = sig2
        if r1 != r2:
            raise ValueError("r values do not match")
        h1 = self.msg2int(msg1)
        h2 = self.msg2int(msg2)
        nonce = (h2 - h1) * pow(s2 - s1, -1, self.n) % self.n
        sk = (s1*nonce - h1) * pow(r1, -1, self.n) % self.n
        return sk, nonce



# =============================================================================
# Derived class
# =============================================================================

class ECDSA(ECDSA_Base):

    def __init__(self, curve_name: str, hash_name: str = "sha256"):
        self.curve_name = curve_name
        ec, G, n, _ = get_curve(curve_name)
        super().__init__(ec, G, n, hash_name)

    def __repr__(self)-> str:
        return f"ECDSA('{self.curve_name}', '{self.hash_name}')"

    def __str__(self)-> str:
        return f"ECDSA-{self.curve_name}-{self.hash_name}"



