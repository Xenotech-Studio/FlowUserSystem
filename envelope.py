"""Compatibility shim — moved to ``flops_agent.crypto.envelope``.

Kept so ``from . import envelope`` (user_system/__init__.py, srp_apis.py) and
``user_system.envelope`` keep working after the P1 kernel extraction. Resolved
via the shared ``backend/`` sys.path root.

Note: ``srp_apis.py`` reaches the private ``envelope._resolve_pubkey_path`` — it
is re-exported explicitly below (``import *`` would not carry a private name).

New code should import from ``flops_agent.crypto.envelope`` directly.
"""

from flops_agent.crypto.envelope import *  # noqa: F401,F403
from flops_agent.crypto.envelope import (  # noqa: F401
    EnvelopeError,
    encrypt_envelope,
    reset_pubkey_cache,
    _resolve_pubkey_path,  # private, but used by srp_apis.py:152
)
