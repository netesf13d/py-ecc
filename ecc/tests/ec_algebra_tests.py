# -*- coding: utf-8 -*-
"""
Elliptic curve algebra tests.

EC algebra test vectors from:
    - http://point-at-infinity.org/ecc/nisttv
      addition and multiplication for NIST curves
    - RFC 7748 https://www.rfc-editor.org/rfc/rfc7748
      multiplication for Montgomery curves (Curve25519, Curve448)
EC point codec test vectors from:
    - RFC 7748 https://www.rfc-editor.org/rfc/rfc7748
      Montgomery curves (Curve25519, Curve448)
"""

import random

from ..elliptic_curves.ec import (sqrt_mod,
                                  get_curve,
                                  Weierstrass_Curve,
                                  Montgomery_Curve,
                                  Edwards_Curve)


# =============================================================================
#
# =============================================================================

def test_curve_operations(name: str, test_vectors: list[dict]):
    """
    Test Elliptic_Curve operations:
        - Curve point addition
        - Scalar multiplication
        - Group order
    """
    ec, G, n, _ = get_curve(name)
    test_vectors = [tv for tv in test_vectors if tv['test'] in {"add", "mult"}]
    print(f"Testing operations on curve {name}...")
    for i, tv in enumerate(test_vectors):
        x = int(tv['x'], base=16)
        y = int(tv['y'], base=16)
        if tv['test'] == 'add':
            chk_add = "SUCCESS" if ec.add(G, G) == (x, y) else "FAIL"
            msg = "addition: " + chk_add
        if tv['test'] == 'mult':
            k = int(tv['k'], base=16)
            chk_mult = "SUCCESS" if ec.mult(G, k) == (x, y) else "FAIL"
            msg = f"multiplication (k={hex(k)}): {chk_mult}"
        print(f"test vector {i} - {msg}")
    # test group order
    Gn = ec.mult(G, n)
    chk_order = "SUCCESS" if Gn == ec.identity else "FAIL"
    print(f"test group order: {chk_order}")


def test_codec(name: str, test_vectors: list[dict]):
    """
    Test curve point encoding/decoding.
    """
    ec, *_ = get_curve(name)

    test_vectors = [tv for tv in test_vectors if tv['test'] == "codec"]
    if test_vectors:
        print(f"Testing codec on {name}...")
    for i, tv in enumerate(test_vectors):
        x = int(tv['x'], base=16)
        y = int(tv['y'], base=16)
        enc = bytes.fromhex(tv['enc'])
        test_enc = ec.encode_point((x, y))
        test_dec = ec.decode_point(enc)
        chk_enc = (test_enc == enc)
        chk_dec = (test_dec == (x, y) or test_dec == (x, ec.p-y))
        print(f"test vector {i} - "
              f"encoding: {'SUCCESS' if chk_enc else 'FAIL'}; "
              f"decoding: {'SUCCESS' if chk_dec else 'FAIL'}; ")


def test_curve_equivalence(curve_equivalence: tuple[str, str]):
    """
    Test equivalence between specific pairs of elliptic curves.
    Equivalence between Montgomery form By^2 = x^3 + Ax^2 + x
    and twisted Edwards form -x^2 + y^2 = 1 + dx^2y^2.
    """
    mec, edec = curve_equivalence
    print(f"Testing curve equivalence {mec} <-> {edec}...")
    mec, mG, n, _ = get_curve(mec)
    edec, edG, *_ = get_curve(edec)
    p = mec.p
    
    # Edwards to Montgomery
    mec_ = Montgomery_Curve(*edec.montgomery_form())
    mG_ = edec.montgomery_point(edG)
    a = mec_.A + 2
    sign = a * pow(mec_.B, -1, p) % p
    rescaled_mec = Montgomery_Curve(p, mec_.A, 1)
    chk_curve_eq = (rescaled_mec.A == mec.A and rescaled_mec.B == mec.B)
    rescaled_mG = (mG_[0], mG_[1]*pow(sqrt_mod(sign*a, p), 1, p) % p)
    chk_point_eq = (mG == rescaled_mG)
    
    # Montgomery to Edwards
    edec_ = Edwards_Curve(*mec.edwards_form())
    edG_ = mec.edwards_point(mG)
    rescaled_edec = Edwards_Curve(p, sign, edec_.d * pow(sign*edec_.a, -1, p))
    chk_curve_eq &= (rescaled_edec.a == edec.a and rescaled_edec.d == edec.d)
    rescaled_edG = (edG_[0]*sqrt_mod(sign*edec_.a, p) % p, edG_[1])
    chk_point_eq &= (rescaled_edG == edG)
    
    print(f"curve equivalence: {'SUCCESS' if chk_curve_eq else 'FAIL'}; "
          f"point equivalence: {'SUCCESS' if chk_point_eq else 'FAIL'}")


def test_birational_equivalences():
    """
    Test conversion and equivalence between elliptic curves/curve points
        - Edwards to Montgomery
        - Montgomery to Edwards
        - Montgomery to Weiertrass
    """
    p = 2**255 - 19
    ec = Edwards_Curve(p, random.randint(1, p-1), random.randint(1, p-1))
    # find a random point on curve
    P = (0, 0)
    while not ec.isin(P):
        y = random.randint(1, p-1)
        xx = (y**2 - 1) * pow(ec.d * y**2 - ec.a, -1, p) % p
        try:
            P = (sqrt_mod(xx, p), y)
        except ValueError:
            continue

    print(f"Testing birational equivalence on curve {ec},\nwith point\n{P}...")
    # to Montgomery / to Weierstrass
    mec = Montgomery_Curve(*ec.montgomery_form())
    mP = ec.montgomery_point(P)
    wec = Weierstrass_Curve(*ec.weierstrass_form())
    wP = ec.weierstrass_point(P)
    chk_point_in = mec.isin(mP) and wec.isin(wP)
    # conversion diagram: back to Edwards / Montgomery to Weierstrass
    edec = Edwards_Curve(*mec.edwards_form())
    edP = mec.edwards_point(mP)
    wec_ = Weierstrass_Curve(*mec.weierstrass_form())
    wP_ = mec.weierstrass_point(mP)
    chk_diag = (edP == P and ec.a == edec.a and ec.d == edec.d
                and wP == wP_ and wec.a == wec_.a and wec.b == wec_.b)
    # Group law preservation
    k = random.randint(2, p)
    kP = ec.mult(P, k)
    chk_group = (mec.mult(mP, k) == ec.montgomery_point(kP)
                 and wec.mult(wP, k) == ec.weierstrass_point(kP))
    print(f"point transfer: {'SUCCESS' if chk_point_in else 'FAIL'}; "
          f"conversion diagram: {'SUCCESS' if chk_diag else 'FAIL'}; "
          f"group law preservation: {'SUCCESS' if chk_group else 'FAIL'}; ")


# =============================================================================
# Test vectors
# =============================================================================

curve_P192_test_vectors = [
    {'test': "add",
     'x': "DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
     'y': "DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB"},
    {'test': "mult",
     'k': "400000003803ffffffcfffffe0800000001ffffe03ffff1f",
     'x': "28783BBF6208E1FF0F965FD8DC0C26FF1D8E02B433EDF2F7",
     'y': "A5852BBC44FD8164C1ABA9A3EC7A88E461D5D77ABD743E87"},
    {'test': "mult",
     'k': "ffffffffffffffffffffffff99def836146bc9b1b4d22830",
     'x': "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
     'y': "F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE"},
    ]

curve_P224_test_vectors = []

curve_P256_test_vectors = [
    {'test': "add",
     'x': "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978",
     'y': "07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1"},
    {'test': "mult",
     'k': "11",
     'x': "47776904C0F1CC3A9C0984B66F75301A5FA68678F0D64AF8BA1ABCE34738A73E",
     'y': "AA005EE6B5B957286231856577648E8381B2804428D5733F32F787FF71F1FCDC"},
    {'test': "mult",
     'k': "159d893d4cdd747246cdca43590e13",
     'x': "1B7E046A076CC25E6D7FA5003F6729F665CC3241B5ADAB12B498CD32F2803264",
     'y': "BFEA79BE2B666B073DB69A2A241ADAB0738FE9D2DD28B5604EB8C8CF097C457B"},
    ]

curve_P384_test_vectors = []

curve_P521_test_vectors = [
    {'test': "add",
     'x': "00433C219024277E7E682FCB288148C282747403279B1CCC06352C6E5505D769BE"
          "97B3B204DA6EF55507AA104A3A35C5AF41CF2FA364D60FD967F43E3933BA6D783D",
     'y': "00F4BB8CC7F86DB26700A7F3ECEEEED3F0B5C6B5107C4DA97740AB21A29906C42D"
          "BBB3E377DE9F251F6B93937FA99A3248F4EAFCBE95EDC0F4F71BE356D661F41B02"},
    {'test': "mult",
     'k': "11",
     'x': "01B00DDB707F130EDA13A0B874645923906A99EE9E269FA2B3B4D66524F2692508"
          "58760A69E674FE0287DF4E799B5681380FF8C3042AF0D1A41076F817A853110AE0",
     'y': "0085683F1D7DB16576DBC111D4E4AEDDD106B799534CF69910A98D68AC2B22A132"
          "3DF9DA564EF6DD0BF0D2F6757F16ADF420E6905594C2B755F535B9CB7C70E64647"},
    {'test': "mult",
     'k': "159d893d4cdd747246cdca43590e13",
     'x': "017E1370D39C9C63925DAEEAC571E21CAAF60BD169191BAEE8352E0F54674443B2"
          "9786243564ABB705F6FC0FE5FC5D3F98086B67CA0BE7AC8A9DEC421D9F1BC6B37F",
     'y': "01CD559605EAD19FBD99E83600A6A81A0489E6F20306EE0789AE00CE16A6EFEA2F"
          "42F7534186CF1C60DF230BD9BCF8CB95E5028AD9820B2B1C0E15597EE54C4614A6"},
    ]

curve_Curve25519_test_vectors = [
    {'test': "mult",
      'k': "4000000000000000000000000000000000000000000000000000000000000008",
     'x': "7930ae1103e8603c784b85b67bb897789f27b72b3e0b35a1bcd727627a8e2c42",
     'y': "456bb2ff86caad1f487f46679e496de718a6edc34fb9ba9d21a93947812d7599"},
    {'test': "codec",
     'x': "7930ae1103e8603c784b85b67bb897789f27b72b3e0b35a1bcd727627a8e2c42",
     'y': "456bb2ff86caad1f487f46679e496de718a6edc34fb9ba9d21a93947812d7599",
     'enc': "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"},
    ]

curve_Curve448_test_vectors = [
    {'test': "mult",
     'k': "80000000000000000000000000000000000000000000000000000000"
          "00000000000000000000000000000000000000000000000000000004",
     'x': "1341cfa9bcb3c29b8b8633f8510b35af2c4939620897b80dcda8234d"
          "6a842baec26507f37af64bfd14dcd91197ee466c1eb0199f8a2c483f",
     'y': "d4eb01ec3f54ded52550dc692c14e85e708229318578291b712a1a48"
          "b0f8debff3923ff90d02d3a278f16921d0f089e6e2c0edcc1856889d"},
    {'test': "codec",
     'x': "1341cfa9bcb3c29b8b8633f8510b35af2c4939620897b80dcda8234d"
          "6a842baec26507f37af64bfd14dcd91197ee466c1eb0199f8a2c483f",
     'y': "d4eb01ec3f54ded52550dc692c14e85e708229318578291b712a1a48"
          "b0f8debff3923ff90d02d3a278f16921d0f089e6e2c0edcc1856889d",
     'enc': "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a"
            "4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"},
    ]

curve_Edwards25519_test_vectors = [
    {'test': "codec",
     'x': "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
     'y': "6666666666666666666666666666666666666666666666666666666666666658",
     'enc': "5866666666666666666666666666666666666666666666666666666666666666"},
    {'test': "birational_equivalence",
     'tgt': 'Curve25519',
     'scale': "076d08",
     'y': "6666666666666666666666666666666666666666666666666666666666666658",
     'enc': "5866666666666666666666666666666666666666666666666666666666666666"},
    ]

curve_Edwards448_test_vectors = []


curve_test_vectors = {
    'P-192': curve_P192_test_vectors,
    'P-224': curve_P224_test_vectors,
    'P-256': curve_P256_test_vectors,
    'P-384': curve_P384_test_vectors,
    'P-521': curve_P521_test_vectors,

    'Curve25519': curve_Curve25519_test_vectors,
    'Curve448': curve_Curve448_test_vectors,

    'Ed25519': curve_Edwards25519_test_vectors,
    'Ed448': curve_Edwards448_test_vectors,
    }


# =============================================================================
# Curve equivalences
# =============================================================================

curve_equivalence_tests = [
    ("curve25519", "edwards25519"), # RFC 7748
    ]


# =============================================================================
#
# =============================================================================

def test_ec_algebra(curve_operations: bool = True,
                    codecs: bool = True,
                    curve_equivalences: bool = True,
                    birational_equivalences: int = 3):
    if curve_operations:
        print("========== Test curve operations ==========")
        for name, test_vectors in curve_test_vectors.items():
            test_curve_operations(name, test_vectors)
        print("")
    if codecs:
        print("========== Test point encoding/decoding ==========")
        for name, test_vectors in curve_test_vectors.items():
            test_codec(name, test_vectors)
        print("")
    if curve_equivalences:
        print("========== Test curve equivalences ==========")
        for curve_equivalence in curve_equivalence_tests:
            test_curve_equivalence(curve_equivalence)
        print("")
    if birational_equivalences:
        print("========== Test birational equivalences ==========")
        for _ in range(birational_equivalences):
            test_birational_equivalences()
        print("")
