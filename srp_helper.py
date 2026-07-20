"""Compatibility shim — moved to ``flops_agent.crypto.srp``.

Kept so ``from . import srp_helper`` (user_system/__init__.py, srp_apis.py) and
``user_system.srp_helper`` keep working after the P1 kernel extraction. The
kernel package is resolved via the shared ``backend/`` sys.path root (same
mechanism as every other backend import); it is not installed separately.

New code should import from ``flops_agent.crypto.srp`` directly.
"""

from flops_agent.crypto.srp import *  # noqa: F401,F403
from flops_agent.crypto.srp import (  # noqa: F401  explicit re-export (mirrors old __all__)
    ARGON2_HASH_LEN,
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    SRP_BITS_RANDOM,
    SRP_BITS_SALT,
    compute_verifier,
    derive_srp_password,
    generate_salt_hex,
    server_start_challenge,
    server_verify_proof,
)
