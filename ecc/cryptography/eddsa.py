# -*- coding: utf-8 -*-
"""
Implementation of the Edwards-Curve Digital Signature Algorithm (EdDSA) from
RFC 8032 https://www.rfc-editor.org/rfc/rfc8032


"""

from typing import Callable
from hashlib import sha512, shake_256

from ..elliptic_curves.ec import CurvePoint, Edwards_Curve, get_curve


Ed25519_hash = lambda m: sha512(m).digest()
Ed448_hash = lambda m: shake_256(m).digest(114)


# =============================================================================
# Elliptic Curve Digital Signature Algorithm base class
# =============================================================================

class EdDSA():
    """
    Implementation of the EdDSA algorithm for:
        - secret key generation <keygen>
        - public key generation <Public_key>
        - signature <sign>
        - signature verification <verify>
    """

    def __init__(self,
                 elliptic_curve: Edwards_Curve,
                 G: CurvePoint,
                 n: int,
                 digest: Callable,
                 prefix: bytes = b'',
                 phflag: bool = False,
                 prehash: Callable | None = None):
        """
        Create an EdDSA instance with custom parameters as described in
        RFC 8032 sections 5.1 and 5.2.

        Five instances are standardized in RFC 8032, using curves:
            - edwards25519 and edwards448,
        with three variants:
            - Pure EdDSA
            - Hash EdDSA (`ph`, for PreHash)
            - Context EdDSA (`ctx`, for Context; only for X25519)
        These instances should created with the dedicated subclasses.

        Parameters
        ----------
        elliptic_curve, G, n : Edwards_Curve, CurvePoint, int
            - The elliptic curve (in Edwards form),
            - A subgroup generator,
            - The order of the subgroup <G>.
            RFC 8032 specifies the following curves:
            - Ed25519 : edwards25519
            - Ed448 : edwards448
        digest : Callable
            Hash function used to digest the message to produce both a nonce
            and the message digest.
            RFC 8032 specifies the following hash functions:
            - Ed25519 : SHA-512
            - Ed448 : SHAKE256(114)
        prefix : bytes, optional
            A prefix added to the message (or its prehash) before signature
            through the <dom> method.
            The default is b''.
            RFC 8032 specifies the following prefixes:
            - Ed25519 : b''
            - Ed25519ctx/ph : b'SigEd25519 no Ed25519 collisions'
            - Ed448 : b'SigEd448'
        phflag : bool, optional
            Enables the `ph` mode of operation.
            The default is False.
        prehash : Callable | None, optional
            Pre-Hash function applied to the message before signing.
            The default is None (prehash is the identity).
            RFC 8032 specifies the following prehash:
            - Ed25519ph : SHA512
            - Ed448ph : SHAKE256(64)
        """
        self.ec = elliptic_curve
        self.G = G
        self.n = n
        self.nbits = self.ec.p.bit_length()
        self.nbytes = self.nbits//8 + 1

        self.digest = digest

        self.prefix = prefix

        if phflag and prehash is None:
            raise ValueError("a prehash mush be provided is phflag is set")
        self.phflag = phflag
        self.prehash = prehash


    def dom(self, context: bytes = b'')-> bytes:
        """
        Add an additional prefix to the message depending on the prefix
        prefix attribute and a variable `context`.
        - An empty context returns only the prefix attribute.
        - A non-empty context is used used in the `ctx` variant.
        """
        if not self.prefix:
            return b''
        if len(context) > 255:
            raise ValueError("context must be <= 255 bytes long")
        dom_ = self.prefix
        dom_ += self.phflag.to_bytes(1, 'big')
        dom_ += len(context).to_bytes(1, 'big')
        dom_ += context
        return dom_


    def keygen(self, sk: bytes)-> tuple[int, bytes]:
        """
        Secret key generation from a bytes sequence for EdDSA.
        """
        if len(sk) != self.nbytes:
            raise ValueError(f"secret key must be {self.nbytes} bytes long")
        h = self.digest(sk)
        s = int.from_bytes(h[:self.nbytes], byteorder='little')
        s &= (1 << self.nbits-1) - 8
        s |= 1 << self.nbits-1
        return s, h[self.nbytes:]


    def sign(self, msg: bytes, sk: bytes, context: bytes = b'')-> bytes:
        """
        Sign a message with EdDSA.

        The signature takes as inputs the message `msg` (bytes), the secret key
        `sk` (int), an optional `context` (for the 'ctx' variant) and returns a
        byte string R + S with
          R = r.G, encoded as bytes
          s = r + h*s (mod n), encoded as bytes
        where
          n is the order of the subgroup <G>
          s is generated from the secret key
          r is the nonce, a digest of the message, a sk-derived value and a
            context-derived value
          h is the hash, a digest of the message, the context-derived value,
            the public key, and R
        """
        msg = self.prehash(msg) if self.phflag else msg
        dom = self.dom(context)

        s, prefix = self.keygen(sk)
        pk = self.ec.encode_point(self.ec.mult(self.G, s))

        r = self.digest(dom + prefix + msg)
        r = int.from_bytes(r, byteorder='little') % self.n
        R = self.ec.encode_point(self.ec.mult(self.G, r))

        h = self.digest(dom + R + pk + msg)
        h = int.from_bytes(h, byteorder='little') % self.n
        S = ((r + h*s) % self.n).to_bytes(self.nbytes, byteorder='little')
        return R + S


    def verify(self,
               msg: bytes,
               sig: bytes,
               pk: bytes,
               context: bytes = b'')-> bool:
        """
        Verify the EdDSA signature `sig` of a message `msg` associated to
        public key `pk` with optional `context` (for the ctx variant).

        With:
          R = r.G
          S = (r + h*s) (mod n)
        Compute h from the message, context, public key and R; then the
        verification is
          S.G = R + h.pk
        """
        msg = self.prehash(msg) if self.phflag else msg
        dom = self.dom(context)

        if len(sig) != 2*self.nbytes:
            msg = f"expected bytes of len {2*self.nbytes}"
            raise ValueError("invalid signature format: " + msg)
        if len(pk) != self.nbytes:
            msg = f"expected bytes of len {self.nbytes}"
            raise ValueError("invalid public_key format: " + msg)
        R = sig[:self.nbytes]
        S = int.from_bytes(sig[self.nbytes:], byteorder='little')
        if S >= self.n:
            return False
        h = self.digest(dom + R + pk + msg)
        h = int.from_bytes(h, byteorder='little') % self.n
        self.ec.decode_point(pk)
        R, pk = self.ec.decode_point(R), self.ec.decode_point(pk)
        return self.ec.mult(self.G, S) == self.ec.add(self.ec.mult(pk, h), R)


    def public_key(self, sk: bytes)-> bytes:
        """
        Returns the public key associated to the secret sk.
        """
        s, _ = self.keygen(sk)
        pk = self.ec.mult(self.G, s)
        return self.ec.encode_point(pk)


# =============================================================================
# Derived classes
# =============================================================================

class Ed25519(EdDSA):

    def __init__(self):
        ec, G, n, _ = get_curve('Ed25519')
        super().__init__(ec, G, n, digest=Ed25519_hash,
                         prefix=b'', phflag=0)


class Ed25519ph(EdDSA):

    def __init__(self):
        ec, G, n, _ = get_curve('Ed25519')
        super().__init__(ec, G, n, digest=Ed25519_hash,
                         prefix=b'SigEd25519 no Ed25519 collisions',
                         phflag=1, prehash=Ed25519_hash)


class Ed25519ctx(EdDSA):

    def __init__(self):
        ec, G, n, _ = get_curve('Ed25519')
        super().__init__(ec, G, n, digest=Ed25519_hash,
                         prefix=b'SigEd25519 no Ed25519 collisions',
                         phflag=0)


class Ed448(EdDSA):

    def __init__(self):
        ec, G, n, _ = get_curve('Ed448')
        super().__init__(ec, G, n, digest=Ed448_hash,
                         prefix=b'SigEd448', phflag=0)


class Ed448ph(EdDSA):

    def __init__(self):
        ec, G, n, _ = get_curve('Ed448')
        super().__init__(ec, G, n, digest=Ed448_hash,
                         prefix=b'SigEd448',
                         phflag=1, prehash=lambda m: shake_256(m).digest(64))


def eddsa_obj(name: str):
    name = name.lower()
    if name == 'ed25519':
        return Ed25519()
    if name == 'ed25519ph':
        return Ed25519ph()
    if name == 'ed25519ctx':
        return Ed25519ctx()
    if name == 'ed448':
        return Ed448()
    if name == 'ed448ph':
        return Ed448ph()
    raise ValueError(f"EdDSA identifier {name} not recognized")
