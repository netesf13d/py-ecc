# -*- coding: utf-8 -*-
"""
Implementation of partially known nonces attack on ECDSA.
"""

from decimal import Decimal

import numpy as np
import numpy.typing as npt
from flint import fmpz_mat


# =============================================================================
#
# =============================================================================

def signatures_to_hnp(signatures: list[tuple[int, int]],
                      q: int,
                      nlsb: int,
                      known_vals: list[int] | int,
                      hashes: list[int] | int)-> list[tuple[int, int]]:
    """
    Convert a list of ECDSA signatures obtained with partially known nonces
    into pairs of numbers corresponding to the hidden number problem.

    The ECDSA congruence is x*r = s*k - h mod q, with
        - (r, s) the signature
        - h the hash of the signed message
        - k the nonce, of which we know LSBs; k = b*2^nlsb + a with a known
        - x the secret to determine

    The corresponding hidden number problem associated to this signature is
    |(t*x - u) mod q| < 2^(nlsb+1) with:
        t = r * 2^(-nlsb) * s^(-1) mod q
        u = 2^(-nlsb) * (a - s^(-1) * h) mod q + q // 2^(nlsb+1)

    For more details, see
    - "The Insecurity of the Elliptic Curve Digital Signature Algorithm with
       Partially Known Nonces" - Nguyen and Shparlinski
      https://dl.acm.org/doi/abs/10.1007/s00145-002-0021-3
    - "Mathematics of Public Key Cryptography" - Steven Galbraith, chapter 21.7
      https://www.math.auckland.ac.nz/~sgal018/crypto-book/crypto-book.html
    """
    if isinstance(known_vals, int):
        known_vals = [known_vals] * len(signatures)
    if isinstance(hashes, int):
        hashes = [hashes] * len(signatures)

    hnp_pairs = []
    for (r, s), a, h in zip(signatures, known_vals, hashes):
        # random multiplier
        t = r * pow(2, -nlsb, q) * pow(s, -1, q) % q
        # nlsb approximation of x*t
        u = (pow(2, -nlsb, q) * (a - pow(s, -1, q) * h) % q) + (q >> (nlsb+1))
        hnp_pairs.append((t, u))

    return hnp_pairs


def babai_nearest_plane(basis: npt.NDArray[object],
                        tgt_vect: list[int])-> npt.NDArray[object]:
    """
    Babai nearest plane algorithm to find a good approximation of tgt_vect on
    the lattice spanned by the given lll-reduced basis.

    The vector found in dimension n is the shortest up to a factor 2^(n/2).
    ||tgt_vect - close_vect|| < 2^(n/2) ||tgt_vect - closest_vect||.

    See "Mathematics of Public Key Cryptography" - Steven Galbraith, chapter 18
    https://www.math.auckland.ac.nz/~sgal018/crypto-book/crypto-book.html

    Parameters
    ----------
    basis : 2D np.ndrray[object] of int
        LLL-reduced basis vectors in row format.
    tgt_vect : list[int]
        The target vector.

    Returns
    -------
    close_vect : 1D np.ndarray of int
        Babai short vector on the lattice spanned by basis.

    Examples
    --------
    >>> B = np.array([[1, 2, 3], [3, 0, -3], [3, -7, 3]], dtype=object)
    >>> w = [10, 6, 5]
    >>> babai_nearest_plane(B, w)
    array([10, 8, 6], dtype=object)

    """
    ## Gram-Schmidt orthogonalization
    norms = []
    ortho_basis = np.full_like(basis, Decimal(0), dtype=object)
    for i, b in enumerate(basis):
        ortho_basis[i] += b
        for j, b_ortho in enumerate(ortho_basis[:i]):
            b_ = ortho_basis[i]
            ortho_basis[i] = b_ - np.dot(b_, b_ortho) / norms[j] * b_ortho
        norms.append(np.dot(ortho_basis[i], ortho_basis[i]))
    ## Find short vector
    close_vect = np.array([0] * len(tgt_vect), dtype=object)
    residue = np.array([Decimal(ui) for ui in tgt_vect], dtype=object)
    for b, b_ortho, norm in zip(basis[::-1], ortho_basis[::-1], norms[::-1]):
        ci = np.dot(residue, b_ortho) / norm
        ci_ = round(ci)
        residue -= ci_ * b # - (ci - ci_) * b_ortho
        close_vect += ci_ * b
    return close_vect


def partially_known_nonces_attack(hnp_pairs: list[tuple[int, int]],
                                  q: int,
                                  nlsb: int)-> int:
    """
    Recover the secret x from an hidden number problem system
    (hnp_pairs, q, nlsb) such that:
        |(ti*x - ui) mod q| < 2^(nlsb+1) with (ti, ui) in hnp_pairs

    The procedure can be summarized as followws:
        - Build a lattice such that the vector (x*ti mod q, i = 1..k)
          is on the lattice. This vector will be very close to the known
          approximation (ui, i = 1..k)
        - LLL-reduce the lattice.
        - Find a close vector using Babai nearest plane method.
        - The vector thus obtained is (x*ti mod q, i = 1..k) with high
          probability, provided we apply Babai method on an LLL-reduced basis.

    For the details, see
    "Mathematics of Public Key Cryptography" - Steven Galbraith,
    chapters 18 and 21.7
    https://www.math.auckland.ac.nz/~sgal018/crypto-book/crypto-book.html

    Remarks:
        - In contrast with the texbook, the whole lattice is dilated by a
          factor 2^(nlsb+1) so that its coordinates are integers.
        - The number of HNP pairs required to get the correct result with
          high probability is about (3*log2(q) + nlsb-1) / nlsb.
          In practice, the algorithm seems to work with half that value.
    """
    n = len(hnp_pairs)
    ## Build lattice and LLL reduce
    lattice = [[q * 2**(nlsb+1) if j == i else 0 for j in range(n)] + [0]
               for i in range(n)]
    lattice.append([ti * 2**(nlsb+1) for ti, _ in hnp_pairs] + [1])
    lattice = fmpz_mat(lattice)
    lll_basis = np.array(lattice.lll().tolist(), dtype=object)
    for idx, x in np.ndenumerate(lll_basis):
        lll_basis[idx] = int(x)
    ## Find Babai short vector
    tgt_vect = [u*2**(nlsb+1) for _, u in hnp_pairs] + [0]
    close_vect = babai_nearest_plane(lll_basis, tgt_vect)
    ## Recover the secret
    alphas = [(vi >> nlsb+1) * pow(ti, -1, q) % q
              for vi, (ti, _) in zip(close_vect, hnp_pairs)]
    if any(close_vect[-1] % q != a for a in alphas):
        print("problem in secret recovery")
        return alphas
    return alphas[0]
