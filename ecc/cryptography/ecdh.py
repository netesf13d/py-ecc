# -*- coding: utf-8 -*-
"""
Implementation of Elliptic Curve Diffie-Hellman (ECDH) secret sharing algorithm
from RFC 7748 https://www.rfc-editor.org/rfc/rfc7748
"""

from typing import TypeAlias
from hashlib import sha512, shake_256

from ..elliptic_curves.ec import CurvePoint, Elliptic_Curve, get_curve


Ed25519_hash = lambda m: sha512(m).digest()
Ed448_hash = lambda m: shake_256(m).digest(114)

Signature: TypeAlias = tuple[int, int]


# =============================================================================
# Elliptic Curve Diffie-Hellman Base class
# =============================================================================

class ECDH():

    def __init__(self,
                 elliptic_curve: Elliptic_Curve,
                 G: CurvePoint,
                 n: int,
                 h: int):
        """
        Create an ECDH instance with custom parameters.

        Parameters
        ----------
        elliptic_curve : Elliptic_Curve
            The elliptic curve.
        G : CurvePoint
            A subgroup generator.
        n : int
            The subgroup order Card(<G>).
        h : int
            The cofactor : Card(elliptic_curve) = n*h.
        """
        self.ec = elliptic_curve
        self.G = G # group generator
        self.n = n # group order
        self.h = h # cofactor
        self.nbits = self.n.bit_length()


    @staticmethod
    def decode_scalar(s: bytes):
        """
        Decode a scalar from a bytes string into an int.
        Not implemented for generic curves.
        """
        msg = "conversion from bytes to scalar not implemented"
        raise NotImplementedError(msg)


    def convert_scalar(self, s: int | bytes)-> int:
        """
        Convert a scalar s to int if provided as a byte string.
        Verify that s is valid for ECDH: 1 <= s <= h*n - 1.
        """
        if isinstance(s, bytes):
            s = self.decode_scalar(s)
        # print(s, hex(s), hex(self.n))
        if s < 1 or s >= self.h*self.n - 1:
            raise ValueError("invalid scalar")
        return s


    def convert_curve_point(self, P: bytes)-> CurvePoint:
        """
        Decode curve point P and check that it is valid for ECDH:
            - P is on the curve
            - P is not the identity
        """
        P = self.ec.decode_point(P)
        self.ec.check_points(P)
        if P == self.ec.identity:
            raise ValueError("public key is the identity")
        return P


    def public_key(self, sk: int | bytes)-> bytes:
        """
        Public key from the secret sk.
        """
        s = self.convert_scalar(sk)
        pk = self.ec.mult(self.G, s)
        return self.ec.encode_point(pk)


    def ecdh(self,
             sk_A: int | bytes,
             pk_B: bytes,
             use_cofactor: bool = False)-> bytes:
        """
        Diffie-Hellman secret generation.

        From self secret `sk_A` and other public key `pk_B` (= sk_B.G),
        construct the shared secret s = sk_A.pk_B = sk_B.pk_A.

        Setting `use_cofactor` provides resistance to small subgroup attacks.
        """
        s = self.convert_scalar(sk_A)
        # multiply by cofactor if required
        if use_cofactor:
            s *= self.h
        # decode public key and verify
        pk_B = self.convert_curve_point(pk_B)
        # ECDH
        secret = self.ec.mult(pk_B, s)
        if secret == self.ec.identity:
            raise RuntimeError("invalid secret")
        return self.ec.encode_point(secret)


    def ecmqv(self,
              sk1_A: int | bytes, sk2_A: int | bytes,
              pk1_B: bytes, pk2_B: bytes):
        """
        Menezes-Qu-Vanstone key agreement.
        From "SEC 1: Elliptic Curve Cryptography"
        https://www.secg.org/sec1-v2.pdf

        Couldn't find test vectors for that one.
        """
        s1 = self.convert_scalar(sk1_A)
        s2 = self.convert_scalar(sk2_A)
        pk1 = self.convert_curve_point(pk1_B)
        pk2 = self.convert_curve_point(pk2_B)

        L = self.nbits // 2 + self.nbits % 2
        xx = (self.ec.mult(self.G, s2)[0] % 2**L) + 2**L
        s = (s2 + xx*s1) % self.n
        x = (pk2_B[0] % 2**L) + 2**L
        # ECMQV
        secret = self.ec.mult(self.ec.add(pk2, self.ec.mult(pk1, x)), self.h*s)
        if secret == self.ec.identity:
            raise RuntimeError("invalid secret")
        return self.ec.encode_point(secret)


# =============================================================================
# Derived classes
# =============================================================================

class X25519(ECDH):

    def __init__(self):
        ec, G, n, h = get_curve('Curve25519')
        super().__init__(ec, G, n, h)

    @staticmethod
    def decode_scalar(s: bytes)-> int:
        """
        Decode bytes scalar to int according to RFC 7748 section 5.
        """
        if len(s) < 32:
            raise ValueError("encoded scalar must be 32 bytes long")
        s = bytearray(s[:32]) # only 32 bytes are considered
        s[0] &= 0b11111000
        s[-1] &= 0b01111111
        s[-1] |= 0b01000000
        return int.from_bytes(s, byteorder='little')


class X448(ECDH):

    def __init__(self):
        ec, G, n, h = get_curve('Curve448')
        super().__init__(ec, G, n, h)

    @staticmethod
    def decode_scalar(s: bytes)-> int:
        """
        Decode bytes scalar to int according to RFC 7748 section 5.
        """
        if len(s) < 56:
            raise ValueError("encoded scalar must be 56 bytes long")
        s = bytearray(s[:56]) # only 56 bytes are considered
        s[0] &= 0b11111100
        s[-1] |= 0b10000000
        return int.from_bytes(s, byteorder='little')


def ecdh_obj(name: str):
    name = name.lower()
    if name == 'x25519':
        return X25519()
    if name == 'x448':
        return X448()
    raise ValueError(f"ECDH identifier {name} not recognized")



