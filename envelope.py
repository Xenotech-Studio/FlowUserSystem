"""boss-key envelope：用 RSA-4096 OAEP 把原始明文密码封进一个只能由
私钥持有者打开的信封。

设计意图（参见上层方案讨论）：
  - SRP verifier 让服务器能验证密码却看不到明文 → 但服务器永远拿不回明文
  - envelope 给 boss 留一条 "我能拿回任何用户的原密码" 的后门
  - 私钥不在服务器（计划手动迁走），所以即使数据库 + 公钥同时被拖也无法恢复

公钥来源优先级：
  1) 环境变量 USER_SYSTEM_RECOVERY_PUBKEY_PATH
  2) 默认 backend/secrets/steven.pub（相对项目根目录推导）

加密对象：UTF-8 编码的原始密码（注册/改密时由 SDK 同时发上来）。
密文以 base64 字符串落地到 Redis user 记录的 password_envelope 字段。
"""

from __future__ import annotations

import base64
import os
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


DEFAULT_PUBKEY_RELATIVE = Path("backend") / "secrets" / "steven.pub"
ENV_VAR = "USER_SYSTEM_RECOVERY_PUBKEY_PATH"


class EnvelopeError(RuntimeError):
    """所有 envelope 相关错误的统一类型。"""


def _resolve_pubkey_path() -> Path:
    env_path = os.getenv(ENV_VAR)
    if env_path:
        return Path(env_path).expanduser().resolve()
    # 相对项目根：向上找直到看到 backend/ 或到达 / 为止
    cur = Path(__file__).resolve()
    for parent in [cur.parent, *cur.parents]:
        candidate = parent / DEFAULT_PUBKEY_RELATIVE
        if candidate.exists():
            return candidate
    raise EnvelopeError(
        f"recovery pubkey not found; set {ENV_VAR} or put it at backend/secrets/steven.pub"
    )


@lru_cache(maxsize=1)
def _load_pubkey() -> rsa.RSAPublicKey:
    path = _resolve_pubkey_path()
    pem = path.read_bytes()
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise EnvelopeError(f"recovery pubkey at {path} is not RSA")
    if key.key_size < 2048:
        raise EnvelopeError(f"recovery pubkey too small ({key.key_size} bits)")
    return key


def reset_pubkey_cache() -> None:
    """轮换密钥时调用；常规请求路径用不到。"""
    _load_pubkey.cache_clear()


def encrypt_envelope(plaintext_password: str) -> str:
    """把明文密码封进 envelope，返回 base64 字符串。

    每次调用密文都不同（OAEP 内置随机），所以拖库者就算同密码也看不出来碰撞。
    """
    if not isinstance(plaintext_password, str):
        raise TypeError("plaintext_password must be str")
    pubkey = _load_pubkey()
    ciphertext = pubkey.encrypt(
        plaintext_password.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("ascii")


__all__ = [
    "EnvelopeError",
    "encrypt_envelope",
    "reset_pubkey_cache",
]
