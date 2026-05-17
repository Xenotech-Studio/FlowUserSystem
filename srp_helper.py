"""SRP-6a + argon2 客户端预哈希

参数固定：PRIME_2048 + SHA-256；argon2id (t=3, m=64MiB, p=4, len=32)。
所有数值在 Redis / JSON 落地时统一用 hex 字符串；envelope 用 base64。

为什么要 argon2 预哈希：标准 SRP 的 x = H(salt, H(I, ':', P)) 只过一次 SHA。
被拖库时离线暴力速度太快。引入 argon2id(plaintext, salt) 把派生成本拉高
到几百次/秒，强迫攻击者放弃弱密码字典。

argon2 的 salt 复用 SRP 的 salt（同一份 16-byte 随机，per-user）；
服务端只持有 verifier，无法反推 argon2 出来的 srp_password。
"""

from __future__ import annotations

import os
import secrets
from typing import Tuple

from argon2.low_level import Type, hash_secret_raw
from srptools import SRPClientSession, SRPContext, SRPServerSession, constants
from srptools.utils import hex_from


SRP_PRIME = constants.PRIME_2048
SRP_GEN = constants.PRIME_2048_GEN
SRP_HASH = constants.HASH_SHA_256
SRP_BITS_RANDOM = 1024     # a / b 的随机位数
SRP_BITS_SALT = 128        # 16-byte salt

ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_TYPE = Type.ID


def generate_salt_hex() -> str:
    """生成 16-byte 随机 salt（hex 32 字符）。注册时由前端或迁移脚本调用。"""
    return secrets.token_hex(16)


def derive_srp_password(plaintext: str, salt_hex: str) -> str:
    """前端预哈希的服务器等价实现。仅用于迁移脚本 / 自测。

    返回 64 字符 hex（32-byte argon2id 输出）。
    JS 前端必须使用完全相同的 argon2 参数 + 同一份 salt 才能登录成功。
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be str")
    if not salt_hex:
        raise ValueError("salt_hex is required")
    salt_bytes = bytes.fromhex(salt_hex)
    raw = hash_secret_raw(
        secret=plaintext.encode("utf-8"),
        salt=salt_bytes,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=ARGON2_TYPE,
    )
    return raw.hex()


def _make_context(username: str, password: str | None = None) -> SRPContext:
    return SRPContext(
        username,
        password,
        prime=SRP_PRIME,
        generator=SRP_GEN,
        hash_func=SRP_HASH,
        bits_random=SRP_BITS_RANDOM,
        bits_salt=SRP_BITS_SALT,
    )


def compute_verifier(user_id: str, srp_password_hex: str, salt_hex: str) -> str:
    """从 srp_password (= argon2 输出 hex) + salt 算出 verifier。

    迁移脚本用：服务端已知明文 → derive_srp_password → compute_verifier。
    返回 verifier 的 hex 字符串。

    salt 必须以 bytes 形式喂给 hash()，因为客户端的 init_base 是 unhexlify(salt_hex)
    保留原始长度的字节；如果这里转成 int 再走 conv，前导 0 字节会丢，
    导致 leading-zero salt 算出来的 verifier 与客户端不一致（约 1/256 概率）。
    """
    ctx = _make_context(user_id, srp_password_hex)
    salt_bytes = bytes.fromhex(salt_hex)
    x = ctx.get_common_password_hash(salt_bytes)
    v = ctx.get_common_password_verifier(x)
    return _ensure_hex(hex_from(v))


def server_start_challenge(user_id: str, verifier_hex: str) -> Tuple[str, str]:
    """启动一次服务端 SRP 挑战。

    返回 (B_hex, b_hex)。调用方负责把 b_hex/verifier_hex/salt_hex 写进 Redis
    与 session_id 关联，proof 阶段恢复。
    """
    ctx = _make_context(user_id)
    session = SRPServerSession(ctx, verifier_hex)
    return _ensure_hex(session.public), _ensure_hex(session.private)


def server_verify_proof(
    user_id: str,
    verifier_hex: str,
    salt_hex: str,
    b_hex: str,
    A_hex: str,
    M1: str,
) -> Tuple[bool, str | None]:
    """完成 proof 验证。

    成功返回 (True, M2_hex)；失败返回 (False, None)。
    """
    ctx = _make_context(user_id)
    session = SRPServerSession(ctx, verifier_hex, private=b_hex)
    try:
        session.process(A_hex, salt_hex)
        # srptools 的 verify_proof 不做 str/bytes 归一：
        # 库内部 self.key_proof 是 hexlify(bytes) → bytes；前端传过来通常是 str；
        # 直接 == 永远 False。手动归一到 bytes 再比。
        m1_bytes = M1.encode("ascii") if isinstance(M1, str) else M1
        ok = session.verify_proof(m1_bytes)
    except Exception:
        return False, None
    if not ok:
        return False, None
    return True, _ensure_hex(session.key_proof_hash)


# srptools 的 hex_from(int)/(bytes) 返回类型在不同情况下是 str 或 bytes（hexlify 在 py3
# 返回 bytes）。这里统一收敛成 str，避免 JSON 序列化和比较时踩坑。
def _ensure_hex(value) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii")
    return str(value)


__all__ = [
    "ARGON2_HASH_LEN",
    "ARGON2_MEMORY_KIB",
    "ARGON2_PARALLELISM",
    "ARGON2_TIME_COST",
    "compute_verifier",
    "derive_srp_password",
    "generate_salt_hex",
    "server_start_challenge",
    "server_verify_proof",
    "SRP_BITS_RANDOM",
    "SRP_BITS_SALT",
]
