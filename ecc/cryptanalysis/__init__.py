# -*- coding: utf-8 -*-
"""
Cryptanalysis methods for elliptic curve cryptography.
    - Discrete logarithm problem with Pohlig-Hellman and Pollard rho methods
    - Partially known nonces and the hidden number problem

Details about the safety of ECC can be found here:
    https://safecurves.cr.yp.to/
"""

from .dlp import point_order, pollard_rho, pohlig_hellman
from .hnp import signatures_to_hnp, partially_known_nonces_attack
