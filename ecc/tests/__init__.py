# -*- coding: utf-8 -*-
"""
Tests for the ecc module.

The following categories of test are implemented:
    - <test_ec_algebra> : tests for elliptic curve algebra (point addition, 
      multiplication, birational equivalence)
    - <test_ec_cryptography> : tests for ecc protocoles (ECDSA, EdDSA, ECDH)
    - <test_ec_cryptanalysis> : tests for cryptanalysis of ecc (currently only
      hidden number problem)
"""

from .ec_algebra_tests import test_ec_algebra
from .ec_cryptography_tests import test_ec_cryptography
from .ec_cryptanalysis_tests import test_ec_cryptanalysis

