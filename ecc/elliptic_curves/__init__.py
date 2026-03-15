# -*- coding: utf-8 -*-
"""
Implementation of elliptic curve algebra over finite fields of prime order.
The following types of curves are implemented:
    - <Weiertrass_Curve> : Elliptic curves in canonical form
      used for ECDSA and ECDH
    - <Montgomery_Curve> : Montgomery curves
      used for ECDH
    - <Edwards_Curve> : Edwards curves
      used for EdDSA
Along with an utility function:
    - <get_curve> : to load standard curves
"""

from .ec import (WeierstrassCurve,
                 MontgomeryCurve,
                 EdwardsCurve,
                 CurvePoint,
                 get_curve)

