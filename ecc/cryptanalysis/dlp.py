# -*- coding: utf-8 -*-
"""

"""

import random
from math import gcd

from sympy import factorint

from ..elliptic_curves.ec import CurvePoint, Elliptic_Curve


# =============================================================================
#
# =============================================================================

def pollard_rho(G: CurvePoint,
                P: CurvePoint,
                ec: Elliptic_Curve,
                n: int,
                nb_partitions: int = 2**5,
                nb_distinguished: int = 2**9)-> int:
    """
    Pollard rho method for the discrete logarithm problem.

    Find the integer x such that P = x*G.
    - P and G are points of the elliptic curve
    - P is in <G>
    - <G> is of order n which should be prime

    The algorithm has three improvements over the textbook version:
        - The elliptic curve is split into `nb_partitions` points, and the
          pseudo-random walk is Q_(i+1) = Q_i + A_m, Q_i in partition m,
          with A_m = a_m*G + b_m*P initially generated at random.
          (in contrast with the the usual 3-fold partition)
        - The algorithm stores distinguished points, occuring with a
          probability 1/`nb_distinguished`.
          If the walk reaches twice the same point, it will eventually lead to
          the same distinguished point and will generate a collision.
          (in contrast with the use of Floyd's algorithm which may spend a long
          time in a very large cycle)
        - Some cases occur in which the walk ends up in a small cycle
          containing no distinguished point. The current path from the last
          distinguished point is kept in memory to allow for cycle detection in
          this case. To limit computational overhead, points are stored every
          `nb_distinguished` steps.

    Examples
    --------
    >>> p = 1000033
    >>> ec = Weierstrass_Curve(p, 33, 69) # y^2 = x^3 + 33x + 66
    >>> G, n = (0, 736476), 1001041
    >>> m = 156458
    >>> pollard_rho(G, ec.mult(G, m), ec, n)
    156458
    """
    a_vals = tuple(random.randint(2, n-1) for _ in range(nb_partitions))
    b_vals = tuple(random.randint(2, n-1) for _ in range(nb_partitions))
    M_vals = tuple(ec.add(ec.mult(G, a), ec.mult(P, b))
                   for a, b in zip(a_vals, b_vals))
    def walk(Q: CurvePoint, a: int, b: int):
        m = hash(Q[0]) % nb_partitions
        new_Q = ec.add(Q, M_vals[m], check_points=False)
        new_a = (a + a_vals[m]) % n
        new_b = (b + b_vals[m]) % n
        return new_Q, new_a, new_b

    distinguished_points = {}
    a = random.randint(2, n-1)
    Qab = (ec.mult(G, a), a, 0)
    curr_path, count = {}, 0
    while True:
        # Collision at a distinguished point
        if (Q:=Qab[0]) in distinguished_points:
            a1, b1 = Qab[1:]
            a2, b2 = distinguished_points[Q][1:]
            break
        # Q has been visited
        if Q in curr_path:
            a1, b1 = Qab[1:]
            a2, b2 = curr_path[Q][1:]
            break
        # Q is distinguished, add to distinguished elements, reset path
        if hash(Q[0]) % nb_distinguished == 0:
            distinguished_points[Q] = Qab
            a = random.randint(2, n-1)
            Qab = (ec.mult(G, a), a, 0)
            curr_path, count = {}, 0
        # Update path, then walk
        if count == nb_distinguished: # Store path points sparsely
            curr_path[Q] = Qab
            count = 0
        Qab = walk(*Qab)
        count += 1

    if gcd(b2 - b1, n) != 1:
        msg = "a1*G + b1*P = a2*G + b2*P with b2 - b1 != 1 (mod n)"
        raise ValueError("found collision " + msg)
    return (a1 - a2) * pow(b2 - b1, -1, n) % n


def pohlig_hellman(G: CurvePoint,
                   P: CurvePoint,
                   ec: Elliptic_Curve,
                   n: int,
                   n_factors: dict[int, int],
                   bruteforce_thr: int = 512)-> int:
    """
    Pohlig-Hellman algorithm to solve the discrete logarithm problem (DLP)
    P = x*G over the given elliptic curve.

    The idea is to solve the DLP over coprime factors of the group order and
    reconstruct using the chinese remainder theorem.

    Parameters
    ----------
    G, P, ec : CurvePoint, CurvePoint, Weierstrass_Curve
        The DLP is P = x*G over ec for unknown x.
    n, n_factors : int, dict[int, int]
        Order of the subgroup <G> and its factorization n_factors[pi] = mi
        for primes pi such that n = prod(pi^mi).
    bruteforce_thr : int, optional
        Threshold below which the DLP is solved using exhaustive search.
        The default is 512.
    """
    # Get the CRT components on each factor
    crt_logarithms = {}
    for factor, mult in n_factors.items():
        k = factor ** mult
        GG, PP = ec.mult(G, n // k), ec.mult(P, n // k)

        if k < bruteforce_thr:
            for i in range(k):
                if PP == ec.mult(GG, i):
                    crt_logarithms[k] = i
        else:
            crt_logarithms[k] = pollard_rho(GG, PP, ec, k)
    # Reconstruct the logarithm
    discrete_log = 0
    for d, r in crt_logarithms.items():
        n_ = n // d
        discrete_log += r * n_ * pow(n_, -1, d)
    return discrete_log % n


def point_order(P: CurvePoint,
                ec: Elliptic_Curve,
                ec_card: int)-> tuple[int, dict]:
    """
    Compute the order n of the subgroup <P> of an elliptic curve `ec` with
    cardinal `ec_card`. Also returns the factorization of n.

    The cardinal of the curve can be computed using Schoof's algorithm,
    implemented for instance in PARI/GP. For instance, to compute the cardinal
    of the elliptic curve y^2 = x^3 + ax + b over Fp:
      \\ p, a, b = ec.p, ec.a, ec.b
      E = ellinit([a, b]*Mod(1,p));
      ellcard(E)
    """
    factors = factorint(ec_card)
    n = ec_card
    if not ec.mult(P, n) == ec.identity:
        raise ValueError("card_ec*P is not identity")
    n_factors = {}
    for factor, mult in factors.items():
        # n_factors[factor] = mult
        for i in range(mult):
            if ec.mult(P, n // factor) == ec.identity:
                n //= factor
                # n_factors[factor] -= 1
            else:
                n_factors[factor] = mult - i
                break
    # n_factors = {p: m for p, m in n_factors.items() if m > 0}
    return n, n_factors
