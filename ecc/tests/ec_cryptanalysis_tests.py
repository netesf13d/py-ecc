# -*- coding: utf-8 -*-
"""
Tests for cryptanalysis of ECC algorithms.

Test vectors from:
    - http://point-at-infinity.org/ecc/nisttv
      addition and multiplication for NIST curves
    - RFC 7748 https://www.rfc-editor.org/rfc/rfc7748
      multiplication and codec for Montgomery curves (Curve25519, Curve448)
"""

import random

from ..elliptic_curves.ec import build_curve
from ..cryptography import ECDSA
from ..cryptanalysis import (point_order, pohlig_hellman,
                             signatures_to_hnp, partially_known_nonces_attack)

# =============================================================================
# 
# =============================================================================

def test_pohlig_hellman(test_vectors: list[dict]):
    """
    Test Pohlig-Hellman attack on the discrete logarithm problem.
    """
    for i, tv in enumerate(test_vectors):
        ec = build_curve(tv['curve_type'], tv['p'], tv['params'])
        G = tv['G']
        card = tv['card']
        n, n_factors = point_order(G, ec, card)
        # Pohlig-Hellman attack
        sk = random.randint(2, n-1)
        pk = ec.mult(G, sk)
        s = pohlig_hellman(G, pk, ec, n, n_factors)
        #
        chk_attack = "SUCCESS" if s == sk else "FAIL"
        print(f"test vector {i}: {chk_attack}")


def test_partially_known_nonces_attack(nlsb: int = 8,
                                       nb_sig: int | None = None):
    """
    Test partially known nonces attack on ECDSA with nlsb LSBs knowns.
    """
    curve_choices = ['secp384r1', 'secp521r1', 'secp192r1', 'secp256k1',
                     'secp256r1', 'secp224k1', 'secp224r1', 'secp192k1',]
    hash_choices = ['sha256', 'sha3-224', 'sha3-384', 'sha3-512', 'md5',
                    'sha384', 'sha1', 'sha224', 'sha3-256', 'sha512',]
    # Setup ECDSA instance and secret key
    curve_name = random.choice(curve_choices)
    hash_name = random.choice(hash_choices)
    ecdsa = ECDSA(curve_name, hash_name)
    sk = random.randint(2, ecdsa.n-1)

    # random messages and corresponding ECDSA hashes
    nb_sig = (3*ecdsa.nbits + nlsb-1) // nlsb if nb_sig is None else nb_sig
    msgs = [random.randbytes(random.randint(0, 80)) for _ in range(nb_sig)]
    hashes = [ecdsa.msg2int(m) for m in msgs]

    # set random ECDSA nonces, extract partially known values, make signatures
    nonces = [random.randint(2, ecdsa.n-1) for _ in range(nb_sig)]
    known_vals = [k % 2**nlsb for k in nonces]
    sig = [ecdsa.sign(msg, sk, k) for msg, k in zip(msgs, nonces)]
    
    # convert to hidden number pairs, recover secret
    hnp_pairs = signatures_to_hnp(sig, ecdsa.n, nlsb, known_vals, hashes)
    s = partially_known_nonces_attack(hnp_pairs, ecdsa.n, nlsb)

    chk_attack = "SUCCESS" if s == sk else "FAIL"
    print(f"{ecdsa} - {nlsb} LSBs known - {nb_sig} signatures: {chk_attack}")


# =============================================================================
# Test vectors
# =============================================================================

# Curves with smooth cardinal suitable for Pohlig-Hellamn attack were found
# using the PARI/GP script `find_weak_curves.gp`.

pohlig_hellman_test_vectors = [
    {'curve_type': "weierstrass",
     'p': 0xcfbdb2e7e60f05d7389c4cbaed94e97f77c09c3ff5e3aacf,
     'params': (0x80e18bf608d7ea7b7ce5f662601c0a7f8339feeef31508,
                0x977d618b50d483426ddecc37881cf74fd25f6c4e32663fae),
     'G': (0x4b38a7ad81fcf4f17541d048522947ba626b7e845a2be76f,
           0x6ba2e76ad5a295c33682e8e05a9eb1ca237779e582da6c40),
     'card': 0xcfbdb2e7e60f05d7389c4cbb5249c0d768bb53e8f785df3e},
    {'curve_type': "weierstrass",
     'p': 0xbf52c053869a8e6f51e8894365d09e4788b727ec5941734f,
     'params': (0x240956cf81a8dab77a41ea9c3e3d4eab1d1e32bae8bda2a1,
                0x5e58b2edc92ffab04b5e80eb05d585fad8c44234913ec2e8),
     'G': (0x26fb7a01cd2e0496fe52c5fd57024e0bb3f7b5ea6728de35,
           0xab8df27e13fa791923bcd796f38544474b9010d7613bbfa3),
     'card': 0xbf52c053869a8e6f51e8894271265c7c7882ba4ad338cdd2},
    ]


# =============================================================================
# 
# =============================================================================

def test_ec_cryptanalysis(pohlig_hellman: bool = True,
                          partially_known_nonces: int = 2):
    """
    Test elliptic curve crypanalysis:
        - Discrete logarithm problem with Pohlig-Hellman
        - Partially known nonces attack
    """
    if pohlig_hellman:
        print("========== Test Pohlig-Hellman attack ==========")
        test_pohlig_hellman(pohlig_hellman_test_vectors)
    print("")
    if partially_known_nonces:
        print("========== Test partially known nonces attack ==========")
        for _ in range(partially_known_nonces):
            test_partially_known_nonces_attack()
    print("")
