# -*- coding: utf-8 -*-
"""
This package implements elliptic curve cryptography primitives, elliptic curve
algebra, and some cryptanalysis algorithms. It is intended for educational
purposes, and the implementation aims to expose as much as possible the
components to experiment with them.  More specifically, the package provides:

* Elliptic curve cryptography algorithms
    - Elliptic Curve Digital Signature Algorithm (ECDSA)
    - Edwards Curve Digital Signature Algorithm (EdDSA)
    - Elliptic Curve Diffie-Hellman (ECDH) key exchange
* Elliptic curve algebra with different forms of curves
    - Weierstrass curves (the canonical form)
    - Montgomery curves
    - (twisted) Edwards curves
* Some cryptanalysis algorithms
    - Attacks on the discrete logarithm problem
    - Partially known nonces attack on ECDSA

However, this package does NOT provide:

* A fast and secure implementation of the algorithms and elliptic curve
  algebra.
* Support for elliptic curves over finite fields Fq with non-prime q
  (eg q = 2^m).
* Random key generation for the various protocols.


Apart from the `cryptanalysis` module, the package uses only the standard
library. Third party packages are necessary to run cryptanalysis algoritms:
    - numpy https://numpy.org/
    - sympy https://www.sympy.org/ (for integer factorization)
    - python-flint https://pypi.org/project/python-flint/ (for LLL reduction)


References
----------
* "SEC 1: Elliptic Curve Cryptography",
  https://www.secg.org/sec1-v2.pdf
* "SEC 2: Recommended Elliptic Curve Domain Parameters",
  https://www.secg.org/sec2-v2.pdf
* RFC 6090 "Fundamental Elliptic Curve Cryptography Algorithms",
  https://www.rfc-editor.org/rfc/rfc6090
* RFC 6979 "Deterministic Usage of the Digital Signature Algorithm (DSA) and
  Elliptic Curve Digital Signature Algorithm (ECDSA)",
  https://www.rfc-editor.org/rfc/rfc6979
* RFC 7748 "Elliptic Curves for Security",
  https://www.rfc-editor.org/rfc/rfc7748
* RFC 8032 "Edwards-Curve Digital Signature Algorithm (EdDSA)",
  https://www.rfc-editor.org/rfc/rfc8032 
* https://safecurves.cr.yp.to/ ; detailed info about the security of ECC
"""

from .elliptic_curves import get_curve

from .cryptography import ECDSA, eddsa_obj, ecdh_obj