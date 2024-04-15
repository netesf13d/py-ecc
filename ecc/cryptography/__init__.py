# -*- coding: utf-8 -*-
"""
Implementation of the three main cryptographic protocols involving elliptic
curves:
    - Elliptic Curve Digital Signature Algorithm (ECDSA)
      see RFC6979  https://www.rfc-editor.org/rfc/rfc6979
    - Edwards Curve Digital Signature Algorithm (EdDSA)
      see RFC 8032 https://www.rfc-editor.org/rfc/rfc8032
    - Elliptic Curve Diffie-Hellman (ECDH)
      see RFC 7748 https://www.rfc-editor.org/rfc/rfc7748
"""

from .ecdsa import ECDSA, ECDSA_Base
from .eddsa import EdDSA, eddsa_obj
from .ecdh import ECDH, ecdh_obj


