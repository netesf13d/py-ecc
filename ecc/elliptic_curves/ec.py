# -*- coding: utf-8 -*-
"""
Implementation of elliptic curve algebra over finite fields of prime order.
The following types of curves are implemented:
    - <Elliptic_Curve> : Base class for elliptic curves
    - <Weiertrass_Curve> : Elliptic curves in canonical form
      used for ECDSA and ECDH
    - <Montgomery_Curve> : Montgomery curves
      used for ECDH
    - <Edwards_Curve> : Edwards curves
      used for EdDSA
Along with utility functions:
    - <sqrt_mod> : Compute a square root mod prime p, used to reconstruct
      curves points from a single coordinate
    - <get_curve> : to load standard curves

Addition and scalar multiplication are implemented without particular care
for performance or security (chord and tangent rule; using regular instead of
homogeneous coordinates...).
"""

from typing import TypeAlias
from math import inf

from .ec_params import EC_PARAMS


CurvePoint: TypeAlias = tuple[int, int] | tuple[inf, inf]


# =============================================================================
# utils
# =============================================================================

def sqrt_mod(a: int, p: int):
    """
    Tonelli-Shanks algorithm to find a square root mod prime p.
    Returns the smallest square root.
    """
    if pow(a, (p-1)//2, p) == p-1:
        raise ValueError(f"a = {a} is not a quadratic residue")
    # shortcuts if a = 0 or p % 4 = 3
    if a == 0:
        return 0
    if p % 4 == 3:
        return pow(a, (p+1)//4, p)
    # decompose p-1 = q * 2**s, q odd
    s = bin(p-1)[::-1].find('1')
    q = (p-1) // 2**s
    # find a quadratic non-residue
    for z in range(p-1):
        if pow(z, (p-1)//2, p) == p-1:
            break
    #
    c, u = pow(z, q, p), pow(a, q, p)
    r = pow(a, (q+1)//2, p)
    for i in range(s-1, 0, -1):
        if pow(u, 2**(i-1), p) == p-1:
            u = u*c**2 % p
            r = r*c % p
        c = pow(c, 2, p)
    return min(r, p - r)


# =============================================================================
# Base class
# =============================================================================

class Elliptic_Curve():
    """
    Base class for elliptic curves over finite prime fields.
    """
    identity = (inf, inf) # The point at infinity

    def __init__(self, p: int):
        """
        Only elliptic curves over finite fields Fp with prime p and p != 2, 3
        are allowed.

        The curve in Weierstrass (canonical) form is defined by the equation
        y^2 = x^3 + ax + b  (mod p) with non-vanishing discriminant
        4a^3 + 27b^2 != 0 (mod p).

        Notes
        -----
        The initializer actually does not check if p is prime.
        """
        if p <= 0:
            raise ValueError("p must be a positive prime")
        if p == 2 or p == 3:
            raise ValueError("Fp characteristic must not be 2 nor 3")
        self.p = p


    def eq_components(self):
        """
        Components of the curve equation.
        """
        raise NotImplementedError


    def isin(self, P: CurvePoint)-> bool:
        """
        Check whether the curve point belongs to the curve.
        """
        x, y = self.eq_components(P)
        if y == x:
            return True
        return False


    def check_points(self, *args: CurvePoint)-> None:
        """
        Raises ValueError if one of the points is not on the curve.
        """
        for P in args:
            if not self.isin(P):
                msg = f"point {(hex(P[0]), hex(P[1]))} is not on the curve"
                raise ValueError(msg)


    def add(self):
        """
        Add two elements within the elliptic curve.
        """
        raise NotImplementedError


    def mult(self, P: CurvePoint, k: int)-> CurvePoint:
        """
        Compute EC element k.r = P + P + ... + P (k times).
        Montgomery ladder implementation.
        """
        self.check_points(P)
        if P == self.identity:
            return P
        P0 = self.identity
        P1 = P if k >= 0 else self.inv(P)
        for ki in bin(abs(k))[2:]:
            if ki == '0':
                P1 = self.add(P0, P1, check_points=False)
                P0 = self.add(P0, P0, check_points=False)
            else:
                P0 = self.add(P0, P1, check_points=False)
                P1 = self.add(P1, P1, check_points=False)
        # P1 == self.add(r0, P)
        return P0


    def inv(self, P: CurvePoint)-> CurvePoint:
        """
        Compute the inverse P^-1 = (x, -y) of P = (x, y).
        """
        if P == self.identity:
            return P
        return (P[0], -P[1])


# =============================================================================
# Concrete implementations
# =============================================================================

class Weierstrass_Curve(Elliptic_Curve):
    """
    Implementation of an elliptic curve in Weierstrass normal form over the
    finite field Fp.
    
    The Weierstrass curve equation is y^2 = x^3 + ax + b (mod p)
    with non-vanishing discriminant: 4a^3 + 27b^2 != 0 mod p.
    
    Any elliptic curve over a field with characteristic != 2, 3 can be written
    in Weierstrass form.
    """
    curve_form = "weierstrass"

    def __init__(self, p: int, a: int, b: int):
        """
        Weierstrass curve y^2 = x^3 + ax + b (mod p),
        with 4a^3 + 27b^2 != 0 (mod p).
        """
        super().__init__(p)
        if (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p == 0:
            msg = "Curve y^2 = x^3 + ax + b is singular with\n"
            msg += f"p = {p}\na = {a}\nb = {b}"
            raise ValueError(msg)
        self.a = a % p
        self.b = b % p


    def __repr__(self):
        repr_ = (f"Weierstrass_Curve(\n    p={hex(self.p)},\n    "
                 f"a={hex(self.a)},\n    b={hex(self.b)})")
        return repr_


    def __str__(self):
        str_ = "Weierstrass curve y^2 = x^3 + ax + b (mod p)\n"
        str_ += f"p = {hex(self.p)}\na = {hex(self.a)}\nb = {hex(self.b)}"
        return str_


    def eq_components(self, P: CurvePoint)-> tuple[int, int] | tuple[inf, inf]:
        """
        Components (y^2, x^3 + ax + b) of the curve equation.
        """
        if P == self.identity:
            return (inf, inf)
        x, y = P
        lhs = pow(y, 2, self.p) % self.p # left hand side
        rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        return (lhs, rhs)


    def encode_point(self, P: CurvePoint, compress: bool = False)-> bytes:
        """
        Curve point to octet string conversion, from
        "SEC 1: Elliptic Curve Cryptography" section 2.3.3.
        https://www.secg.org/sec1-v2.pdf
        """
        if P == self.identity:
            return b'\x00'
        nbytes = (self.p.bit_length() // 8) + (self.p.bit_length() % 8 > 0)
        if compress:
            enc = (2 + (P[1] & 1) << 8*nbytes) + P[0]
            return enc.to_bytes(nbytes+1, byteorder='big')
        else:
            enc = (4 << 2*8*nbytes) + (P[0] << 8*nbytes) + P[1]
            return enc.to_bytes(2*nbytes+1, byteorder='big')


    def decode_point(self, P: bytes)-> CurvePoint:
        """
        Curve point to octet string conversion, from
        "SEC 1: Elliptic Curve Cryptography" section 2.3.4.
        For a curve point P, P == decode_point(encode_point(P, compress))
        whether `compress` is True or not.
        """
        if P == b'\x00':
            return self.identity
        nbytes = (self.p.bit_length() // 8) + (self.p.bit_length() % 8 > 0)
        if len(P) == nbytes + 1:
            x = int.from_bytes(P[1:], byteorder='big')
            y0 = P[0] & 1
            yy = (x**3 + self.a*x + self.b) % self.p
            y = sqrt_mod(yy, self.p)
            P = (x, y) if y & 1 == y0 else (x, self.p - y)
            self.check_points(P)
            return P
        elif len(P) == 2*nbytes + 1:
            x = int.from_bytes(P[1:nbytes+1], byteorder='big')
            y = int.from_bytes(P[1+nbytes:], byteorder='big')
            self.check_points(P:=(x, y))
            return P
        raise ValueError("invalid point encoding")


    def add(self, P: CurvePoint, Q: CurvePoint,
            check_points: bool = True)-> CurvePoint:
        """
        Add two elements within the elliptic curve.
        Chords and tangents method, slow and insecure.
        """
        if check_points:
            self.check_points(P, Q)
        # One of the points is the identity
        if P == self.identity:
            return Q
        if Q == self.identity:
            return P
        # the points are not the identity
        (x1, y1), (x2, y2) = P, Q
        if x1 != x2:
            s = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
            t = (y1*x2 - y2*x1) * pow(x2 - x1, -1, self.p) % self.p
            x = (s**2 - x1 - x2) % self.p
            y = (- s*x - t) % self.p
            return (x, y)
        else: # x1 == x2
            if y1 != y2: # P = -Q
                return self.identity
            elif y1 == y2 == 0: # P + Q = 2.P = O
                return self.identity
            else: # y1 == y2 != 0
                s = (3*x1**2 + self.a) * pow(2*y1, -1, self.p) % self.p
                x = (s**2 - 2*x1) % self.p
                y = (s*(x1 - x) - y1) % self.p
                return (x, y)



class Montgomery_Curve(Elliptic_Curve):
    """
    Implementation of a Montgomery elliptic curve over the finite field Fp.
    
    The Montgomery curve equation is By^2 = x^3 + Ax^2 + x (mod p),
    with B(A^2 - 4) != 0 (mod p).
    
    Scalar multiplication can be implemented efficiently on Montgomery curves
    (not the case here).
    """
    curve_form = "montgomery"

    def __init__(self, p: int, A: int, B: int):
        """
        Montgomery curve By^2 = x^3 + Ax^2 + x (mod p),
        with B(A^2 - 4) != 0 (mod p)
        """
        super().__init__(p)
        if B * (A**2 - 4) % p == 0:
            msg = "Curve By^2 = x^3 + Ax^2 + x is singular with\n"
            msg += f"p = {p}\nA = {A}\nB = {B}"
            raise ValueError(msg)
        self.A = A % p
        self.B = B % p


    def __repr__(self):
        repr_ = (f"Montgomery_Curve(\n    p={hex(self.p)},\n    "
                 f"A={hex(self.A)},\n    B={hex(self.B)})")
        return repr_


    def __str__(self):
        str_ = "Montgomery curve By^2 = x^3 + Ax^2 + x (mod p)\n"
        str_ += f"p = {hex(self.p)}\nA = {hex(self.A)}\nB = {hex(self.B)}"
        return str_


    def eq_components(self, P: CurvePoint)-> tuple[int, int] | tuple[inf, inf]:
        """
        Return the components (By^2, x^3 + Ax^2 + x) of the curve equation.
        """
        if P == self.identity:
            return (inf, inf)
        x, y = P
        lhs = self.B * pow(y, 2, self.p) # left hand side
        rhs = pow(x, 3, self.p) + self.A * pow(x, 2, self.p) + x
        return (lhs % self.p, rhs % self.p)


    def encode_point(self, P: CurvePoint)-> bytes:
        """
        Point encoding from RFC 7748 section 5.
        https://www.rfc-editor.org/rfc/rfc7748
        """
        if P == self.identity:
            raise ValueError("cannot encode identity")
        nbytes = (self.p.bit_length() // 8) + (self.p.bit_length() % 8 > 0)
        return P[0].to_bytes(nbytes, byteorder='little')


    def decode_point(self, P: bytes)-> CurvePoint:
        """
        Point decoding from RFC 7748 section 5.
        """
        x = int.from_bytes(P, byteorder='little')
        if x >= self.p:
            raise ValueError("invalid point encoding")
        yy = pow(self.B, -1, self.p) * (x**3 + self.A*x**2 + x) % self.p
        y = sqrt_mod(yy, self.p)
        P = (x, y)
        self.check_points(P)
        return P


    def add(self,P: CurvePoint, Q: CurvePoint,
            check_points: bool = True)-> CurvePoint:
        """
        Add two elements within the elliptic curve.
        Chords and tangents method, slow and insecure.
        """
        if check_points:
            self.check_points(P, Q)
        # One of the points is the identity
        if P == self.identity:
            return Q
        if Q == self.identity:
            return P
        # the points are not the identity
        (x1, y1), (x2, y2) = P, Q
        if x1 != x2:
            s = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
            t = (y1*x2 - y2*x1) * pow(x2 - x1, -1, self.p) % self.p
            x = (self.B*s**2 - self.A - x1 - x2) % self.p
            y = (- s*x - t) % self.p
            return (x, y)
        else: # x1 == x2
            if y1 != y2: # P = -Q
                return self.identity
            elif y1 == y2 == 0: # P + Q = 2.P = O
                return self.identity
            else: # y1 == y2 != 0, doubling
                s = (3*x1**2 + 2*self.A*x1 + 1) * pow(2*self.B*y1, -1, self.p)
                s = s % self.p
                x = (self.B*s**2 - self.A - 2*x1) % self.p
                y = (s*(x1 - x) - y1) % self.p
                return (x, y)
    
    
    def weierstrass_form(self)-> tuple[int, int, int]:
        """
        Birational map from Montgomery form to Weierstrass form.
        """
        p = self.p
        a = (3 - self.A**2) * pow(3*self.B**2, -1, p) % p
        b = (2*self.A**3 - 9*self.A) * pow(27*self.B**3, -1, p) % p
        return (p, a, b)


    def weierstrass_point(self, P: CurvePoint)-> CurvePoint:
        """
        Birational map from Montgomery curve point to equivalent Weierstrass
        curve point.
        """
        if P == self.identity:
            return (inf, inf)
        else:
            p, A, B = self.p, self.A, self.B
            x = (P[0]*pow(B, -1, p) + A*pow(3*B, -1, p)) % p
            y = P[1] * pow(B, -1, p) % p
            return (x, y)
    
    
    def edwards_form(self)-> tuple[int, int, int]:
        """
        Birational map from Montgomery form to twisted Edwards form.
        "Twisted Edwards Curves" https://eprint.iacr.org/2008/013.pdf
        """
        a = (self.A + 2) * pow(self.B, -1, self.p) % self.p
        d = (self.A - 2) * pow(self.B, -1, self.p) % self.p
        return (self.p, a, d)


    def edwards_point(self, P: CurvePoint)-> CurvePoint:
        """
        Birational map from Montgomery curve point to equivalent twisted
        Edwards curve point.
        "Twisted Edwards Curves" https://eprint.iacr.org/2008/013.pdf
        """
        if P == self.identity:
            return (0, 1)
        else:
            try:
                x = P[0] * pow(P[1], -1, self.p) % self.p
                y = (P[0]-1) * pow(P[0]+1, -1, self.p) % self.p
            except ValueError:
                raise ValueError(f"curve equivalence invalid at point {P}")
            else:
                return (x, y)    


class Edwards_Curve(Elliptic_Curve):
    """
    Implementation of an (twisted) Edwards curve over the finite field Fp.
    
    The Edwards curve equation is ax^2 + y^2 = 1 + dx^2y^2 (mod p)
    with a, d != 0 mod p.
    
    Point addition and multiplication can be implemented efficiently on
    Edwards curves (not the case here).
    """
    curve_form = "edwards"
    identity = (0, 1)

    def __init__(self, p: int, a: int, d: int):
        """
        Edwards curve ax^2 + y^2 = 1 + dx^2y^2 (mod p),
        with a, d != 0 mod p.
        """
        super().__init__(p)
        if a % p == 0:
            raise ValueError("a = 0 mod p")
        if d % p == 0:
            raise ValueError("d = 0 mod p")
        self.a = a % p
        self.d = d % p


    def __repr__(self):
        repr_ = (f"Edwards_Curve(\n    p={hex(self.p)},\n    "
                 f"a={hex(self.a)},\n    d={hex(self.d)})")
        return repr_


    def __str__(self):
        str_ = "Edwards curve ax^2 + y^2 = 1 + dx^2y^2 (mod p)\n"
        str_ += f"p = {hex(self.p)}\na = {hex(self.a)}\nd = {hex(self.d)}"
        return str_


    def eq_components(self, P: CurvePoint)-> tuple[int, int]:
        """
        Return the components (ax^2 + y^2, 1 + dx^2y^2) of the curve equation.
        """
        x, y = P
        lhs = self.a * pow(x, 2, self.p) + pow(y, 2, self.p)
        rhs = 1 + self.d * pow(x*y, 2, self.p) # right hand side
        return (lhs % self.p, rhs % self.p)


    def encode_point(self, P: CurvePoint)-> bytes:
        """
        Point encoding from RFC 8032 section 5.1.2.
        https://www.rfc-editor.org/rfc/rfc8032
        """
        nbits = self.p.bit_length()
        nbytes = (nbits // 8) + 1
        enc = P[1] + ((P[0] & 1) << (8*nbytes - 1))
        return enc.to_bytes(nbytes, byteorder='little')


    def decode_point(self, P: bytes)-> CurvePoint:
        """
        Point encoding from RFC 8032 section 5.1.3.
        """
        nbits = self.p.bit_length()
        nbytes = (nbits // 8) + 1
        if len(P) != nbytes:
            raise ValueError("invalid point encoding")
        #
        P = int.from_bytes(P, byteorder='little')
        y = P & (2**nbits - 1)
        x0 = P >> (8*nbytes - 1)
        #
        xx = (y**2 - 1) * pow(self.d * y**2 - self.a, -1, self.p) % self.p
        x = sqrt_mod(xx, self.p)
        P = (x, y) if x & 1 == x0 else (self.p - x, y)
        self.check_points(P)
        return P


    def add(self, P: CurvePoint, Q: CurvePoint,
            check_points: bool = True)-> CurvePoint:
        """
        Add two elements within the elliptic curve.
        The group law is significantly different from that of the projective
        plane.
        """
        if check_points:
            self.check_points(P, Q)
        (x1, y1), (x2, y2) = P, Q
        dxxyy = self.d * x1 * x2 * y1 * y2 % self.p
        x = (x1*y2 + x2*y1) * pow(1 + dxxyy, -1, self.p) % self.p
        y = (y1*y2 - self.a*x1*x2) * pow(1 - dxxyy, -1, self.p) % self.p
        return (x, y)


    def inv(self, P: CurvePoint)-> CurvePoint:
        """
        Compute the inverse P^-1 = (-x, y) of P = (x, y).
        """
        return (-P[0], P[1])
    
    
    def montgomery_form(self)-> tuple[int, int, int]:
        """
        Birational map from twisted Edwards form to Montgomery form.
        "Twisted Edwards Curves" https://eprint.iacr.org/2008/013.pdf
        """
        A = 2 * (self.a + self.d) * pow(self.a - self.d, -1, self.p) % self.p
        B = 4 * pow(self.a - self.d, -1, self.p) % self.p
        return (self.p, A, B)


    def montgomery_point(self, P: CurvePoint)-> CurvePoint:
        """
        Birational map from twisted Edwards curve point to equivalent
        Montgomery curve point.
        "Twisted Edwards Curves" https://eprint.iacr.org/2008/013.pdf
        """
        if P == self.identity:
            return (inf, inf)
        else:
            try:
                u = (1+P[1]) * pow(1-P[1], -1, self.p) % self.p
                v = u * pow(P[0], -1, self.p) % self.p
            except ValueError:
                raise ValueError(f"curve equivalence invalid at point {P}")
            else:
                return (u, v)
    
    
    def weierstrass_form(self)-> tuple[int, int, int]:
        """
        Birational map from twisted Edwards form to Weierstrass form.
        """
        # To Montgomery
        A = 2 * (self.a + self.d) * pow(self.a - self.d, -1, self.p) % self.p
        B = 4 * pow(self.a - self.d, -1, self.p) % self.p
        # To Weierstrass
        a = (3 - A**2) * pow(3*B**2, -1, self.p) % self.p
        b = (2*A**3 - 9*A) * pow(27*B**3, -1, self.p) % self.p
        return (self.p, a, b)


    def weierstrass_point(self, P: CurvePoint)-> CurvePoint:
        """
        Birational map from twisted Edwards curve point to equivalent
        Weierstrass curve point.
        """
        if P == self.identity:
            return (inf, inf)
        else:
            p, a, d = self.p, self.a, self.d
            # To Montgomery form
            try:
                u = (1+P[1]) * pow(1-P[1], -1, p) % p
                v = u * pow(P[0], -1, p) % p
            except ValueError:
                raise ValueError(f"curve equivalence invalid at point {P}")
            # To Weierstrass form
            x = (u * (a-d) * pow(4, -1, p) + (a+d) * pow(6, -1, p)) % p
            y = v * (a-d) * pow(4, -1, p) % p
            return (x, y)


# =============================================================================
#
# =============================================================================

def build_curve(curve_type: str,
                p: int,
                params: tuple[int, ...])-> Elliptic_Curve:
    """
    Return the appropriate Elliptic_Curve object depending on `curve_type`.
    """
    if curve_type == "weierstrass":
        return Weierstrass_Curve(p, *params)
    if curve_type == "montgomery":
        return Montgomery_Curve(p, *params)
    if curve_type == "edwards":
        return Edwards_Curve(p, *params)
    raise ValueError("curve_type must be in "
                     "{'weierstrass', 'montgomery', 'edwards'}")


def get_curve(curve_name: str):
    """
    Get one of the standard curve instances avaiable for elliptic curve
    cryptography.

    Returns
    -------
    ec, G, n, l : Elliptic_Curve, CurvePoint, int, int
        - The elliptic curve instance,
        - The appropriate subgroup generator,
        - The orger of the subgroup,
        - The cofactor
    """
    curve_name = curve_name.casefold()
    match curve_name:
        # Weierstrass curves
        case 'secp192k1' | 'ansip192k1':
            curve_type = "weierstrass"
            p, params, G, n, l = EC_PARAMS['secp192k1']
        case 'p-192' | 'secp192r1' | 'prime192v1':
            curve_type = "weierstrass"
            p, params, G, n, l = EC_PARAMS['secp192r1']
        case 'secp224k1' | 'ansip224k1':
            curve_type = "weierstrass"
            p, params, G, n, l = EC_PARAMS['secp224k1']
        case 'p-224' | 'secp224r1' | 'ansip224r1':
            curve_type = "weierstrass"
            p, params, G, n, l = EC_PARAMS['secp224r1']
        case 'secp256k1' | 'ansip256k1':
            curve_type = "weierstrass"
            p, params, G, n, l = EC_PARAMS['secp256k1']
        case 'p-256' | 'secp256r1' | 'prime256v1':
            curve_type = "weierstrass"
            p, params, G, n, l = EC_PARAMS['secp256r1']
        case 'p-384' | 'secp384r1' | 'ansip384r1':
            curve_type = "weierstrass"
            p, params, G, n, l = EC_PARAMS['secp384r1']
        case 'p-521' | 'secp521r1' | 'ansip521r1':
            curve_type = "weierstrass"
            p, params, G, n, l = EC_PARAMS['secp521r1']
        # Montgomery curve_types
        case 'curve25519':
            curve_type = "montgomery"
            p, params, G, n, l = EC_PARAMS['curve25519']
        case 'curve448':
            curve_type = "montgomery"
            p, params, G, n, l = EC_PARAMS['curve448']
        # Edwards curve_types
        case 'ed25519' | 'edwards25519':
            curve_type = "edwards"
            p, params, G, n, l = EC_PARAMS['edwards25519']
        case 'ed448' | 'edwards448':
            curve_type = "edwards"
            p, params, G, n, l = EC_PARAMS['edwards448']

        case _:
            msg = f"available curves are {set(EC_PARAMS.keys())}"
            raise ValueError(f"Incorrect curve name: {curve_name}; " + msg)

    return build_curve(curve_type, p, params), G, n, l