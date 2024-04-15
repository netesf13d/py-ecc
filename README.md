# py-ecc

Python implementation of elliptic curve cryptography primitives, elliptic curve algebra, and some cryptanalysis algorithms. It is intended for educational purposes, and the implementation aims to expose as much as possible the components to experiment with them. The jupyter notebook _ecc_examples.ipynb_ illustrates the use of the package.


## Overview

The package provides:

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

* A fast and secure implementation of the algorithms and elliptic curve algebra.
* Support for elliptic curves over finite fields Fq with non-prime q (eg q = 2^m).
* Random key generation for the various protocols.


## Dependencies

Apart from the `cryptanalysis` module, the package uses only the standard
library. Third party packages are necessary to run cryptanalysis algoritms:
    - numpy https://numpy.org/
    - sympy https://www.sympy.org/ (for integer factorization)
    - python-flint https://pypi.org/project/python-flint/ (for LLL reduction)


## Notes

The typing annotations in the code are by no means rigorous. They are made to facilitate the understanding of the nature of various parameters.


## References

* [_SEC 1: Elliptic Curve Cryptography_](https://www.secg.org/sec1-v2.pdf)
* [_SEC 2: Recommended Elliptic Curve Domain Parameters_](https://www.secg.org/sec2-v2.pdf)
* [RFC 6090](https://www.rfc-editor.org/rfc/rfc6090) _Fundamental Elliptic Curve Cryptography Algorithms_
* [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) _Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)_
* [RFC 7748](https://www.rfc-editor.org/rfc/7748) _Elliptic Curves for Security_
* [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) _Edwards-Curve Digital Signature Algorithm (EdDSA)_
* [https://safecurves.cr.yp.to/](https://safecurves.cr.yp.to/) ; detailed info about the security of ECC
