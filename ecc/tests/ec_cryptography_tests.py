# -*- coding: utf-8 -*-
"""
Tests for the cryptography protocols. The following protocols are tested:
    - Elliptic Curve Digital Signature Algorithm; test vectors from:
        RFC 6979 https://www.rfc-editor.org/rfc/rfc6979
    - Edwards Curve Digital Signature Algorithm; test vectors from:
        RFC 8032 https://www.rfc-editor.org/rfc/rfc8032
    - Elliptic Curve Diffie Hellman; test vectors from:
        RFC 7748 https://www.rfc-editor.org/rfc/rfc7748
"""

from ..cryptography import ECDSA, eddsa_obj, ecdh_obj


# =============================================================================
# Tests
# =============================================================================

def test_ecdsa(name: str, test_vectors: dict):
    """
    Test an ECDSA implementation with given test vectors:
        - public key generation
        - nonce generation
        - Signature
        - Signature verification
        - public key recovery
    """
    ecdsa = ECDSA(name)
    sk = int(test_vectors['sk'], base=16)
    pk = tuple(int(x, base=16) for x in test_vectors['pk'])
    test_vects = test_vectors['tests']
    print(f"Testing {name}...")
    ## Test public key generation
    chk_pk = "SUCCESS" if ecdsa.public_key(sk) == pk else "FAIL"
    print(f"public key generation: {chk_pk}")
    ## Test nonce generation, signature, verification, public key recovery
    for i, tv in enumerate(test_vects):
        ecdsa.set_digest(tv['hash'].lower())
        msg = tv['msg']
        nonce = int(tv['k'], base=16)
        sig = tuple(int(x, base=16) for x in tv['sig'])
        k_test = next(ecdsa.nonce_gen(msg, sk))
        #
        chk_nonce = "SUCCESS" if k_test == nonce else "FAIL"
        chk_sig = "SUCCESS" if ecdsa.sign(msg, sk, nonce) == sig else "FAIL"
        verif = "SUCCESS" if ecdsa.verify(msg, sig, pk) else "FAIL"
        chk_pkr = "SUCCESS" if pk in ecdsa.public_key_recovery(msg, sig) else "FAIL"
        print(f"test vector {i} - nonce generation: {chk_nonce}; "
              f"sign: {chk_sig}; signature verification: {verif}; "
              f"public key recovery: {chk_pkr}")


def test_eddsa(name: str, test_vectors: list[dict]):
    """
    Test an EdDSA implementation with given test vectors:
        - public key generation
        - Signature
        - Signature verification
    """
    eddsa = eddsa_obj(name)
    print(f"Testing {name}...")
    for i, tv in enumerate(test_vectors):
        sk = bytes.fromhex(tv['sk'])
        pk = bytes.fromhex(tv['pk'])
        msg = bytes.fromhex(tv['msg'])
        sig = bytes.fromhex(tv['sig'])
        ctx = bytes.fromhex(tv['context'])
        # check public key generation, signature, and verification
        chk_pk = "SUCCESS" if eddsa.public_key(sk) == pk else "FAIL"
        chk_sig = "SUCCESS" if eddsa.sign(msg, sk, ctx) == sig else "FAIL"
        verif = "SUCCESS" if eddsa.verify(msg, sig, pk, ctx) else "FAIL"
        print(f"test vector {i} - public key: {chk_pk}; "
              f"sign: {chk_sig}; signature verification: {verif}")


def test_ecdh(name: str, test_vectors: list[dict]):
    """
    Test an EdDSA implementation with given test vectors:
        - public key generation
        - Generated secret
    """
    ecdh = ecdh_obj(name)
    print(f"Testing {name}...")
    for i, tv in enumerate(test_vectors):
        skA = bytes.fromhex(tv['skA'])
        pkA = bytes.fromhex(tv['pkA'])
        skB = bytes.fromhex(tv['skB'])
        pkB = bytes.fromhex(tv['pkB'])
        secret = bytes.fromhex(tv['sec'])
        # check public key generation, secret generation
        chk_pkA = "SUCCESS" if ecdh.public_key(skA) == pkA else "FAIL"
        chk_pkB = "SUCCESS" if ecdh.public_key(skB) == pkB else "FAIL"
        chk_secA = "SUCCESS" if ecdh.ecdh(skA, pkB) == secret else "FAIL"
        chk_secB = "SUCCESS" if ecdh.ecdh(skB, pkA) == secret else "FAIL"
        print(f"test vector {i} - "
              f"public key A: {chk_pkA}; public key B: {chk_pkB}; "
              f"secret sharing A: {chk_secA}; secret sharing B: {chk_secB}")


# =============================================================================
# ECDSA test vectors - taken from RFC 6979
# =============================================================================

ECDSA_P192_test_vectors = {
    'sk': "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4",
    'pk': ("AC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56",
           "3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43"),
    'tests': [
        {'msg': b"sample", 'hash': "SHA256",
         'k': "32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496",
         'sig': ("4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55",
                 "CCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85")},
        {'msg': b"sample", 'hash': "SHA512",
         'k': "A2AC7AB055E4F20692D49209544C203A7D1F2C0BFBC75DB1",
         'sig': ("4D60C5AB1996BD848343B31C00850205E2EA6922DAC2E4B8",
                 "3F6E837448F027A1BF4B34E796E32A811CBB4050908D8F67")},
        {'msg': b"test", 'hash': "SHA256",
         'k': "5C4CE89CF56D9E7C77C8585339B006B97B5F0680B4306C6C",
         'sig': ("3A718BD8B4926C3B52EE6BBE67EF79B18CB6EB62B1AD97AE",
                 "5662E6848A4A19B1F1AE2F72ACD4B8BBE50F1EAC65D9124F")}
        ]
    }

ECDSA_P256_test_vectors = {
    'sk': "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
    'pk': ("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
           "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"),
    'tests': [
        {'msg': b"sample", 'hash': "SHA256",
         'k': "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
         'sig': ("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
                 "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")},
        {'msg': b"sample", 'hash': "SHA512",
         'k': "5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5",
         'sig': ("8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00",
                 "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE")},
        {'msg': b"test", 'hash': "SHA256",
         'k': "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0",
         'sig': ("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
                 "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083")}
        ]
    }


ECDSA_P384_test_vectors = {
    'sk': "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA"
          "9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
    'pk': ("EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E"
           "06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
           "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9"
           "F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720"),
    'tests': [
        {'msg': b"sample", 'hash': "SHA256",
         'k': "180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404"
              "B490650A8ACC414E375572342863C899F9F2EDF9747A9B60",
         'sig': ("21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E"
                 "354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
                 "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D4"
                 "5DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0")},
        {'msg': b"sample", 'hash': "SHA512",
         'k': "92FC3C7183A883E24216D1141F1A8976C5B0DD797DFA597E"
              "3D7B32198BD35331A4E966532593A52980D0E3AAA5E10EC3",
         'sig': ("ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047"
                 "C0046861DA4A799CFE30F35CC900056D7C99CD7882433709",
                 "512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA913"
                 "5329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5")},
        {'msg': b"test", 'hash': "SHA256",
         'k': "0CFAC37587532347DC3389FDC98286BBA8C73807285B184C"
              "83E62E26C401C0FAA48DD070BA79921A3457ABFF2D630AD7",
         'sig': ("6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5"
                 "B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B",
                 "2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C"
                 "8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265")}
        ]
    }


ECDSA_P521_test_vectors = {
    'sk': "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA"
          "896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
    'pk': ("1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371"
           "123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
           "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A"
           "0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"),
    'tests': [
        {'msg': b"sample", 'hash': "SHA256",
         'k': "0EDF38AFCAAECAB4383358B34D67C9F2216C8382AAEA44A3DAD5FDC9C325757617"
              "93FEF24EB0FC276DFC4F6E3EC476752F043CF01415387470BCBD8678ED2C7E1A0",
         'sig': ("1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D1"
                 "6876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
                 "04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4"
                 "F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC")},
        {'msg': b"sample", 'hash': "SHA512",
         'k': "1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B"
              "1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3",
         'sig': ("0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174"
                 "E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA",
                 "0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282"
                 "623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A")},
        {'msg': b"test", 'hash': "SHA256",
         'k': "01DE74955EFAABC4C4F17F8E84D881D1310B5392D7700275F82F145C61E843841A"
              "F09035BF7A6210F5A431A6A9E81C9323354A9E69135D44EBD2FCAA7731B909258",
         'sig': ("00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042E"
                 "B28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8",
                 "0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FD"
                 "E00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86")}
        ]
    }

ECDSA_test_vectors = {
    'P-192': ECDSA_P192_test_vectors,
    'P-256': ECDSA_P256_test_vectors,
    'P-384': ECDSA_P384_test_vectors,
    'P-521': ECDSA_P521_test_vectors,
    }


# =============================================================================
# EdDSA test vectors - taken from RFC8032
# =============================================================================

Ed25519_test_vectors = [
    {'sk': "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     'pk': "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     'msg': "",
     'sig': "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
     'context': ""},
    {'sk': "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     'pk': "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     'msg': "af82",
     'sig': "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
     'context': ""},
    ]

Ed25519ctx_test_vectors = [
    {'sk': "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
     'pk': "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
     'msg': "f726936d19c800494e3fdaff20b276a8",
     'sig': "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a"
            "8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d",
     'context': "666f6f"},
    {'sk': "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
     'pk': "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
     'msg': "f726936d19c800494e3fdaff20b276a8",
     'sig': "fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3"
            "216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d",
     'context': "626172"},
    ]

Ed25519ph_test_vectors = [
    {'sk': "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     'pk': "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     'msg': "616263",
     'sig': "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
            "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
     'context': ""},
    ]

Ed448_test_vectors = [
    {'sk': "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef"
           "6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
     'pk': "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d8"
           "0e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
     'msg': "",
     'sig': "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d"
            "41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980"
            "ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac"
            "5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
     'context': ""},
    {'sk': "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a"
           "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
     'pk': "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086"
           "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
     'msg': "03",
     'sig': "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2"
            "151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da"
            "1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d"
            "5428407e85dcbc98a49155c13764e66c3c00",
     'context': "666f6f"},
    ]

Ed448ph_test_vectors = [
    {'sk': "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
           "ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49",
     'pk': "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743"
           "c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880",
     'msg': "616263",
     'sig': "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae38"
            "1f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd"
            "433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3"
            "ad203df7dc7ce360c3cd3696d9d9fab90f00",
     'context': ""},
    {'sk': "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
           "ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49",
     'pk': "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743"
           "c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880",
     'msg': "616263",
     'sig': "c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa48"
            "1065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3"
            "653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab7128"
            "4f8d0704a608c54a6b62d97beb511d132100",
     'context': "666f6f"},
    ]


EdDSA_test_vectors = {
    'Ed25519': Ed25519_test_vectors,
    'Ed25519ctx': Ed25519ctx_test_vectors,
    'Ed25519ph': Ed25519ph_test_vectors,
    'Ed448': Ed448_test_vectors,
    'Ed448ph': Ed448ph_test_vectors
    }


# =============================================================================
# ECDH test vectors - taken from RFC 7748
# =============================================================================

X25519_test_vectors = [
    {'skA': "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
     'pkA': "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
     'skB': "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
     'pkB': "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
     'sec': "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"},
    ]

X448_test_vectors = [
    {'skA': "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
            "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
     'pkA': "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
            "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
     'skB': "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
            "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
     'pkB': "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
            "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
     'sec': "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
            "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"},
    ]

ECDH_test_vectors = {
    'X25519': X25519_test_vectors,
    'X448': X448_test_vectors,
    }


# =============================================================================
# 
# =============================================================================

def test_ec_cryptography(ecdsa: bool = True,
                         eddsa: bool = True,
                         ecdh: bool = True):
    """
    Test elliptic curve cryptography protocols:
        - ECDSA
        - EdDSA
        - ECDH
    """
    if ecdsa:
        print("========== Test ECDSA ==========")
        for name, test_vectors in ECDSA_test_vectors.items():
            test_ecdsa(name, test_vectors)
        print("")
    if eddsa:
        print("========== Test EdDSA ==========")
        for name, test_vectors in EdDSA_test_vectors.items():
            test_eddsa(name, test_vectors)
        print("")
    if ecdh:
        print("========== Test ECDH ==========")
        for name, test_vectors in ECDH_test_vectors.items():
            test_ecdh(name, test_vectors)
        print("")


