"""SRP-6a 登录 + 改密 + 公钥下发的 API 路由。

与现有 /api/login 等明文路径并存，逐步取代。客户端流程：

  注册（host 自己的注册流程比如 /api/auth/register 调用 set_srp_credentials）:
    前端：salt = random; srp_pw = argon2(plaintext, salt);
          verifier = SRP_g^x mod N; envelope = RSA-OAEP(plaintext, steven.pub)
    后端：set_srp_credentials(redis, user_id, salt, verifier, envelope)

  登录:
    POST /api/srp/login/challenge   { id }
      → { session_id, salt, B }
    POST /api/srp/login/proof       { session_id, A, M1, device_name? }
      → { M2, access_token, user, message }

  改密（需 Bearer token + 用旧密码做一次 SRP 证明）:
    1. POST /api/srp/login/challenge { id }                    # 服务端不知道这是改密前置
       → { session_id, salt, B }
    2. POST /api/srp/change_password
          headers: Authorization: Bearer <current_token>
          body: { old_session_id, old_A, old_M1, salt, verifier, envelope }
       → { ok }
    super_command="just do it" 时跳过 old_* 校验，对齐旧 /api/change_user_password 行为。
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

import redis
from fastapi import FastAPI, Header, HTTPException

from . import envelope, srp_helper


SRP_CHALLENGE_TTL_SEC = 300       # 挑战在 5 分钟内必须完成 proof
ACCESS_TOKEN_TTL_SEC = 30 * 24 * 60 * 60  # 与旧 /api/login 保持一致


def _challenge_key(session_id: str) -> str:
    return f"srp_challenge:{session_id}"


def set_srp_credentials(
    r_user: redis.Redis,
    user_id: str,
    salt_hex: str,
    verifier_hex: str,
    envelope_b64: str,
) -> None:
    """把 SRP 凭据写入 user:{user_id}。
    调用方负责自身鉴权（已经验证用户身份后才调用）。

    顺手把老的 password 字段抹掉，避免明文残留与 SRP 字段并存。
    """
    key = f"user:{user_id}"
    raw = r_user.get(key)
    if not raw:
        raise HTTPException(status_code=404, detail="User not found")
    user = json.loads(raw)
    user["srp_salt"] = salt_hex
    user["srp_verifier"] = verifier_hex
    user["password_envelope"] = envelope_b64
    user.pop("password", None)
    r_user.set(key, json.dumps(user).encode("utf-8"))


def register_srp_apis(
    app: FastAPI,
    *,
    get_user_redis: Callable[[FastAPI], redis.Redis],
    get_user_id_from_token: Callable[[str, redis.Redis], Optional[str]],
    issue_access_token: Callable[[redis.Redis, str, str], str],
    pubkey_path_resolver: Optional[Callable[[], Path]] = None,
) -> None:
    """挂上 SRP 路由。

    参数:
      get_user_redis(app) -> Redis
      get_user_id_from_token(token, r) -> user_id|None
      issue_access_token(r, user_id, device_name) -> access_token
        登录成功后用于发 token；复用 user_apis 的设备名复用 / TTL 策略。
      pubkey_path_resolver: 仅用于覆盖 /api/srp/pubkey 暴露的密钥文件路径（测试用）。
    """

    def _resolve_pubkey() -> Path:
        if pubkey_path_resolver is not None:
            return pubkey_path_resolver()
        # envelope 模块已经做过路径解析，复用它的结果
        return envelope._resolve_pubkey_path()

    @app.get("/api/srp/pubkey")
    async def get_recovery_pubkey():
        """返回 boss recovery 公钥的 PEM。客户端注册/改密时用它生成 envelope。

        公钥本身公开无害；私钥不在服务器，泄露公钥不影响登录安全。
        """
        path = _resolve_pubkey()
        try:
            pem = path.read_text()
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="recovery pubkey not configured")
        return {"pubkey_pem": pem}

    @app.post("/api/srp/login/challenge")
    async def srp_login_challenge(payload: dict):
        user_id = (payload.get("id") or "").strip()
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required")
        r_user = get_user_redis(app)
        raw = r_user.get(f"user:{user_id}")
        if not raw:
            raise HTTPException(status_code=404, detail="User not found")
        user = json.loads(raw)
        salt_hex = user.get("srp_salt")
        verifier_hex = user.get("srp_verifier")
        if not salt_hex or not verifier_hex:
            # 老用户尚未迁移；引导调用方走旧 /api/login 或先做迁移
            raise HTTPException(status_code=409, detail="SRP credentials not set for user")

        B_hex, b_hex = srp_helper.server_start_challenge(user_id, verifier_hex)
        session_id = uuid.uuid4().hex
        r_user.set(
            _challenge_key(session_id),
            json.dumps(
                {
                    "user_id": user_id,
                    "salt": salt_hex,
                    "verifier": verifier_hex,
                    "b": b_hex,
                    "created_at": int(time.time()),
                }
            ).encode("utf-8"),
            ex=SRP_CHALLENGE_TTL_SEC,
        )
        return {"session_id": session_id, "salt": salt_hex, "B": B_hex}

    @app.post("/api/srp/login/proof")
    async def srp_login_proof(payload: dict):
        session_id = (payload.get("session_id") or "").strip()
        A_hex = (payload.get("A") or "").strip()
        M1 = (payload.get("M1") or "").strip()
        device_name = payload.get("device_name") or "Unknown Device"
        if not session_id or not A_hex or not M1:
            raise HTTPException(status_code=400, detail="session_id / A / M1 are required")

        r_user = get_user_redis(app)
        ck = _challenge_key(session_id)
        ch_raw = r_user.get(ck)
        if not ch_raw:
            raise HTTPException(status_code=403, detail="Challenge expired or unknown")
        challenge = json.loads(ch_raw)
        # 挑战是一次性的：无论验证成败都立刻删，挡重放
        r_user.delete(ck)

        ok, M2_hex = srp_helper.server_verify_proof(
            challenge["user_id"],
            challenge["verifier"],
            challenge["salt"],
            challenge["b"],
            A_hex,
            M1,
        )
        if not ok:
            raise HTTPException(status_code=403, detail="Authentication failed")

        user_id = challenge["user_id"]
        user_raw = r_user.get(f"user:{user_id}")
        if not user_raw:
            raise HTTPException(status_code=404, detail="User not found")
        user = json.loads(user_raw)

        access_token = issue_access_token(r_user, user_id, device_name)
        # user 出参不暴露 SRP 内部字段（verifier 是核心秘密；envelope 是 boss 后门）
        public_user = {
            k: v for k, v in user.items()
            if k not in ("srp_verifier", "password_envelope", "password")
        }
        return {
            "message": "Login successful",
            "M2": M2_hex,
            "access_token": access_token,
            "user": public_user,
        }

    @app.post("/api/srp/change_password")
    async def srp_change_password(payload: dict, authorization: str = Header(None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization header is required")
        bearer = authorization[7:].strip()
        r_user = get_user_redis(app)
        user_id = get_user_id_from_token(bearer, r_user)
        if not user_id:
            raise HTTPException(status_code=403, detail="Invalid access token")

        new_salt = (payload.get("salt") or "").strip()
        new_verifier = (payload.get("verifier") or "").strip()
        new_envelope = (payload.get("envelope") or "").strip()
        if not new_salt or not new_verifier or not new_envelope:
            raise HTTPException(status_code=400, detail="salt / verifier / envelope are required")

        super_command = payload.get("super_command")
        if super_command != "just do it":
            # 必须通过一次 SRP proof 证明持有旧密码
            old_session_id = (payload.get("old_session_id") or "").strip()
            old_A = (payload.get("old_A") or "").strip()
            old_M1 = (payload.get("old_M1") or "").strip()
            if not old_session_id or not old_A or not old_M1:
                raise HTTPException(
                    status_code=400,
                    detail="old_session_id / old_A / old_M1 are required (or pass super_command)",
                )

            ck = _challenge_key(old_session_id)
            ch_raw = r_user.get(ck)
            if not ch_raw:
                raise HTTPException(status_code=403, detail="Old-password challenge expired")
            challenge = json.loads(ch_raw)
            r_user.delete(ck)

            # 防止有人用别人发起的挑战来改自己的密码（或反过来）
            if challenge.get("user_id") != user_id:
                raise HTTPException(status_code=403, detail="Challenge user mismatch")

            ok, _ = srp_helper.server_verify_proof(
                user_id,
                challenge["verifier"],
                challenge["salt"],
                challenge["b"],
                old_A,
                old_M1,
            )
            if not ok:
                raise HTTPException(status_code=400, detail="Old password is incorrect")

        set_srp_credentials(r_user, user_id, new_salt, new_verifier, new_envelope)
        return {"message": "Password changed successfully"}


__all__ = ["register_srp_apis", "set_srp_credentials"]
