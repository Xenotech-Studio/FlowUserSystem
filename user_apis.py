"""
User APIs
用户相关的所有 API 路由定义和业务逻辑

本文件包含用户系统相关的所有 API，包括：
- 用户信息管理（获取、创建、更新、删除）
- 用户认证（登录、登出、验证）
- 密码管理（修改密码）
- 头像上传
"""

from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Depends, Cookie, Response, Body
from fastapi.responses import JSONResponse
from typing import Any, Callable, Optional
import json
import time
import uuid
import warnings
import redis
import os

# 历史遗留：上传能力曾内嵌在 user_system 内（self.cos_upload）。
# 现在已抽到独立 submodule flow_upload。register_user_apis 支持以参数注入
# file_to_url；为 None 时回退到 self.cos_upload（带 DeprecationWarning），
# 兼容尚未切换到 flow_upload 的接入方。

# Flops 使用可选的 config.py，无 config_default 模块；与 cos_upload.file_to_url 默认 bucket 一致
_DEFAULT_USER_SYSTEM_COS_BUCKET = "flowtask-1302933783"
try:
    import config as _config  # type: ignore
    _bucket = getattr(_config, "USER_SYSTEM_COS_BUCKET", None)
    if isinstance(_bucket, str) and _bucket.strip():
        USER_SYSTEM_COS_BUCKET = _bucket.strip()
    else:
        USER_SYSTEM_COS_BUCKET = _DEFAULT_USER_SYSTEM_COS_BUCKET
except ImportError:
    USER_SYSTEM_COS_BUCKET = _DEFAULT_USER_SYSTEM_COS_BUCKET
from .hooks import UserHooks
from .srp_apis import register_srp_apis

# Redis 默认连接配置（可被 init_user_redis 参数覆盖）
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_USER_DB = 7  # 用户系统 Redis 数据库编号

# 用户信息字段配置
visitor_userinfo_keys = ["id", "nickname", "avatarUrl"]
# 自己访问自己信息时也要藏起来的字段。
# - password: 明文密码（migrate strip 后理论上不存在，留着兜底）
# - srp_verifier: SRP 核心秘密；前端 KDK 派生 + login 验证用不到，给出去只会
#   给 offline crack 添帮手
# - password_envelope: boss-recovery 后门，与用户日常无关
# - k_user_envelope / k_user_recovery_blob: 也是 recovery-only，前端无需取
self_userinfo_keys_mask = [
    "password",
    "srp_verifier",
    "password_envelope",
    "k_user_envelope",
    "k_user_recovery_blob",
]

# -------------------- 跨域 SSO Cookie 配置 --------------------
# 同账号在 .xenotech.studio 各子域（e-store-00 ~ e-store-08）共享登录态。
# 与 Authorization: Bearer header 并存，header 优先；浏览器以外的客户端继续走 header。
SSO_COOKIE_NAME = "estore_access_token"
SSO_COOKIE_DOMAIN = ".xenotech.studio"
SSO_COOKIE_MAX_AGE = 30 * 24 * 60 * 60  # 与 access token TTL 对齐


def _set_sso_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SSO_COOKIE_NAME,
        value=token,
        domain=SSO_COOKIE_DOMAIN,
        path="/",
        samesite="lax",
        secure=True,
        httponly=True,
        max_age=SSO_COOKIE_MAX_AGE,
    )


def _clear_sso_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SSO_COOKIE_NAME,
        domain=SSO_COOKIE_DOMAIN,
        path="/",
    )

# -------------------- 工具函数 --------------------

def get_user_id_from_token(token: str, redis_user: redis.Redis) -> Optional[str]:
    """从token获取user_id（通过遍历所有access_token键）"""
    # 遍历所有access_token键，查找匹配的token
    all_token_keys = redis_user.keys("access_token:*")
    for token_key in all_token_keys:
        key_parts = token_key.decode('utf-8').split(":")
        if len(key_parts) >= 3 and key_parts[-1] == token:
            # 格式：access_token:{user_id}:{token}
            user_id = key_parts[1]
            # 验证token是否有效
            if redis_user.exists(token_key):
                return user_id
    return None

def check_access_token(token: str, user_id: str, redis_user: redis.Redis):
    """检查 access token 是否有效"""
    key = f"access_token:{user_id}:{token}"
    if not redis_user.exists(key):
        return False, ""
    token_value_raw = redis_user.get(key)
    device_name = token_value_raw.decode('utf-8') if token_value_raw else ""
    return True, device_name


# -------------------- Token 元数据（is_manual 等）旁路存储 --------------------
# access_token:{user_id}:{token}        →  device_name (str)        [主 key，向后兼容]
# access_token_meta:{user_id}:{token}   →  JSON {"is_manual": ..., "created_at": ...}
# 缺失 meta 视为登录产生的普通 token（is_manual=False）。

def _token_meta_key(user_id: str, token: str) -> str:
    return f"access_token_meta:{user_id}:{token}"


def _load_token_meta(redis_user: redis.Redis, user_id: str, token: str) -> dict:
    raw = redis_user.get(_token_meta_key(user_id, token))
    if not raw:
        return {}
    try:
        s = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw)
        data = json.loads(s)
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def _save_token_meta(redis_user: redis.Redis, user_id: str, token: str, meta: dict, ttl_seconds: Optional[int]) -> None:
    """ttl_seconds=None 表示永不过期（与主 key 的 PERSIST 行为一致）。"""
    key = _token_meta_key(user_id, token)
    payload = json.dumps(meta, ensure_ascii=False).encode("utf-8")
    if ttl_seconds is None:
        redis_user.set(key, payload)
    else:
        redis_user.set(key, payload, ex=int(ttl_seconds))


def _delete_token_meta(redis_user: redis.Redis, user_id: str, token: str) -> None:
    redis_user.delete(_token_meta_key(user_id, token))


def _is_manual_token(redis_user: redis.Redis, user_id: str, token: str) -> bool:
    return bool(_load_token_meta(redis_user, user_id, token).get("is_manual"))


def issue_or_reuse_access_token(redis_user: redis.Redis, user_id: str, device_name: str) -> str:
    """登录成功后发 access token。优先复用同 device_name 的现有 token（手动 token 除外）；
    没有就新建 30 天 TTL 的 token。

    抽出来给 /api/login 与 /api/srp/login/proof 共用，行为必须一致。
    """
    existing_token: Optional[str] = None
    for token_key in redis_user.keys(f"access_token:{user_id}:*"):
        token_value_raw = redis_user.get(token_key)
        if not token_value_raw:
            continue
        if token_value_raw.decode("utf-8") != device_name:
            continue
        candidate = token_key.decode("utf-8").split(":")[-1]
        if _is_manual_token(redis_user, user_id, candidate):
            continue
        existing_token = candidate
        redis_user.expire(token_key, 30 * 24 * 60 * 60)
        break

    if existing_token:
        lookup_key = f"access_token_lookup:{existing_token}"
        # 兼容老 token：若 lookup key 不存在则补建（迁移逻辑）
        if not redis_user.exists(lookup_key):
            redis_user.set(lookup_key, user_id, ex=30 * 24 * 60 * 60)
        else:
            redis_user.expire(lookup_key, 30 * 24 * 60 * 60)
        return existing_token

    new_token = uuid.uuid4().hex
    redis_user.set(
        f"access_token:{user_id}:{new_token}",
        device_name.encode("utf-8"),
        ex=30 * 24 * 60 * 60,
    )
    # 存储反向映射：access_token -> user_id，用于从 Cookie 恢复身份
    redis_user.set(f"access_token_lookup:{new_token}", user_id, ex=30 * 24 * 60 * 60)
    return new_token

def get_current_user_id(authorization: str = Header(None)) -> str:
    """
    从请求头获取当前用户ID（用于需要认证的API）
    
    注意：此函数需要在 register_user_apis 之后使用，因为它依赖于 app.state.redis_user
    如果需要在其他模块中使用，请使用 create_get_current_user_id_dependency 创建依赖
    """
    from fastapi import Request
    # 这里需要从请求中获取 app，但直接使用会有问题
    # 更好的方式是创建一个依赖工厂函数
    raise NotImplementedError("请使用 create_get_current_user_id_dependency 创建依赖")

def create_get_current_user_id_dependency(app: FastAPI):
    """
    创建 get_current_user_id 依赖函数
    
    用法:
        get_current_user_id = create_get_current_user_id_dependency(app)
        
        @app.get("/api/some_endpoint")
        async def some_endpoint(user_id: str = Depends(get_current_user_id)):
            ...
    """
    def _get_current_user_id(
        authorization: str = Header(None),
        estore_access_token: Optional[str] = Cookie(None),
    ) -> str:
        """获取当前用户ID。

        优先使用 Authorization: Bearer header；若缺失则回退到跨域 SSO
        Cookie（.xenotech.studio 域下的 estore_access_token），用于在
        e-store-00 ~ e-store-08 子域之间共享登录态。
        """
        token: Optional[str] = None
        if authorization:
            if not authorization.startswith("Bearer "):
                raise HTTPException(status_code=401, detail="Invalid authorization format")
            token = authorization[7:]  # 移除 "Bearer " 前缀
        elif estore_access_token:
            token = estore_access_token

        if not token:
            raise HTTPException(status_code=401, detail="Authorization header or SSO cookie is required")

        # 从token获取user_id
        r_user = get_user_redis(app)
        user_id = get_user_id_from_token(token, r_user)
        if not user_id:
            raise HTTPException(status_code=403, detail="Invalid access token")

        return user_id

    return _get_current_user_id

# -------------------- 数据库初始化 --------------------

def get_user_redis(app: FastAPI) -> redis.Redis:
    """
    获取用户系统 Redis 客户端（供业务层复用）。

    用法:
        from user_system import get_user_redis
        r_user = get_user_redis(app)
        r_user.set("my:biz:key", "value")
    """
    r_user = getattr(app.state, "redis_user", None)
    if r_user is None:
        raise RuntimeError("app.state.redis_user 尚未初始化，请先调用 init_user_redis / register_user_apis")
    return r_user


def init_user_redis(
    app: FastAPI,
    *,
    redis_host: Optional[str] = None,
    redis_port: Optional[int] = None,
    redis_db: Optional[int] = None,
):
    """
    初始化用户系统的 Redis 连接。

    优先级：
      1) 显式参数（redis_host/redis_port/redis_db）
      2) 环境变量（FLOWSYS_REDIS_HOST/FLOWSYS_REDIS_PORT/FLOWSYS_REDIS_DB）
      3) 模块默认值（REDIS_HOST/REDIS_PORT/REDIS_USER_DB）
    """
    resolved_host = redis_host or os.getenv("FLOWSYS_REDIS_HOST", REDIS_HOST)
    resolved_port = int(redis_port if redis_port is not None else os.getenv("FLOWSYS_REDIS_PORT", REDIS_PORT))
    resolved_db = int(redis_db if redis_db is not None else os.getenv("FLOWSYS_REDIS_DB", REDIS_USER_DB))

    @app.on_event("startup")
    def _startup_user_redis():
        # redis_user: 存储用户相关数据（用户信息、访问令牌）
        app.state.redis_user = redis.Redis(
            host=resolved_host, port=resolved_port, db=resolved_db, decode_responses=False
        )
    
    @app.on_event("shutdown")
    def _shutdown_user_redis():
        r_user = app.state.redis_user
        if r_user:
            r_user.close()

# -------------------- API 路由定义 --------------------

def register_user_apis(
    app: FastAPI,
    hooks: Optional[UserHooks] = None,
    *,
    register_redis_init: bool = True,
    redis_host: Optional[str] = None,
    redis_port: Optional[int] = None,
    redis_db: Optional[int] = None,
    after_user_saved: Optional[Callable[[str], None]] = None,
    before_user_key_deleted: Optional[Callable[[str], None]] = None,
    file_to_url: Optional[Callable[..., str]] = None,
    avatar_bucket: Optional[str] = None,
    avatar_folder: str = "AVATARS",
):
    """
    注册所有用户相关的 API 路由和数据库初始化
    
    参数:
      app: FastAPI 应用实例
      hooks: 可选的用户操作钩子，用于在用户创建/更新/删除时执行自定义逻辑
      register_redis_init: 若为 False，则不再注册 init_user_redis（适用于已在别处调用过 init_user_redis 的场景）
      redis_host/redis_port/redis_db: 用户系统 Redis 覆盖配置
      after_user_saved: 宿主集成回调。在 Redis 写入 user:{id} 且已调用 hooks 的 created/updated 之后执行，签名为 (user_id) -> None；异常会向上抛出（与原先内联业务逻辑一致）。
      before_user_key_deleted: 宿主集成回调。在 hooks.call_user_deleted 之后、删除 user:{id} 键之前执行，签名为 (user_id) -> None；用于清理依赖 Flow 用户 ID 的扩展数据等。
      file_to_url: 头像上传函数（签名 (file, folder_name=..., bucket=..., ...) → 公网 URL）。
                   推荐传入 `flow_upload.file_to_url`。为 None 时回退到 user_system 自带的
                   `cos_upload.file_to_url`（已废弃，会发 DeprecationWarning）。
      avatar_bucket: 头像 COS bucket；不传时使用模块级 `USER_SYSTEM_COS_BUCKET` 的解析值。
      avatar_folder: 头像 COS 路径前缀（默认 "AVATARS"）。
    
    返回:
      get_current_user_id: 可用于 Depends 的依赖函数，用于获取当前用户ID
    """
    # 初始化用户系统的 Redis 连接（可与路由注册分离，以保证路由顺序与 startup 顺序可控）
    if register_redis_init:
        init_user_redis(app, redis_host=redis_host, redis_port=redis_port, redis_db=redis_db)
    
    # 如果没有提供hooks，创建一个空的
    if hooks is None:
        hooks = UserHooks()
    
    # 创建 get_current_user_id 依赖函数
    get_current_user_id_dep = create_get_current_user_id_dependency(app)

    # ----- 解析头像上传依赖 -----
    # 优先级：注入 → 兼容回退到 self.cos_upload（带 deprecation 警告）
    _avatar_file_to_url: Optional[Callable[..., str]] = file_to_url
    if _avatar_file_to_url is None:
        try:
            from .cos_upload import file_to_url as _builtin_file_to_url  # type: ignore
        except ImportError:
            _builtin_file_to_url = None
        if _builtin_file_to_url is not None:
            warnings.warn(
                "user_system.register_user_apis: 未注入 file_to_url，已回退到 user_system.cos_upload。"
                " 推荐显式传入 flow_upload.file_to_url；user_system 内置上传实现将在未来版本移除。",
                DeprecationWarning,
                stacklevel=2,
            )
        _avatar_file_to_url = _builtin_file_to_url
    _avatar_bucket = avatar_bucket if avatar_bucket else USER_SYSTEM_COS_BUCKET
    
    @app.get("/api/users")
    async def get_users(super_command: str = None):
        """Retrieve all users from Redis. not commonly used."""
        r_user = app.state.redis_user
        if super_command == "just do it":
            # 如果是超级命令，返回所有用户信息
            users = []
            keys = r_user.keys("user:*")
            for key in keys:
                user_info_raw = r_user.get(key)
                if user_info_raw:
                    user_info = json.loads(user_info_raw)
                    users.append(user_info)
        else:
            # 否则只返回部分用户信息
            users = []
            keys = r_user.keys("user:*")
            for key in keys:
                user_info_raw = r_user.get(key)
                if user_info_raw:
                    user_info = json.loads(user_info_raw)
                    processed_user_info = {k: v for k, v in user_info.items() if k in visitor_userinfo_keys}
                    users.append(processed_user_info)
        return users

    @app.get("/api/user/{user_id}")
    async def get_user(user_id: str, access_token: str = None):
        """Retrieve a single user by ID"""
        r_user = app.state.redis_user
        key = f"user:{user_id}"
        if not r_user.exists(key):
            raise HTTPException(status_code=404, detail="User not found")
        
        user_info_raw = r_user.get(key)
        userInfo = json.loads(user_info_raw)
        is_self = False
        
        # 检查 access token 是否存在
        if access_token:
            authed, device_name = check_access_token(access_token, user_id, r_user)
            if not authed:
                raise HTTPException(status_code=403, detail="Invalid access token")
            # 如果有 access token，返回完整用户信息
            is_self = True

        processedUserInfo = {}
        
        if not is_self:
            # 如果不是访问自己的用户信息，则只返回部分信息
            processedUserInfo = {k: v for k, v in userInfo.items() if k in visitor_userinfo_keys}
        else:
            # 如果是访问自己的用户信息，则返回完整信息，但按照mask隐藏部分字段
            processedUserInfo = {k: v for k, v in userInfo.items() if k not in self_userinfo_keys_mask}
        
        return processedUserInfo

    @app.post("/api/user")
    async def update_or_create_user(user_data: dict):
        """Add or update a user in Redis"""
        r_user = app.state.redis_user
        user_id = user_data.get("id")
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required")
        key = f"user:{user_id}"
        if r_user.exists(key):
            # 更新用户信息
            existing_user_raw = r_user.get(key)
            existing_user = json.loads(existing_user_raw)
            existing_user.update(user_data)
            r_user.set(key, json.dumps(existing_user).encode('utf-8'))
            hooks.call_user_updated(user_id, existing_user, r_user)
            payload_user = existing_user
            msg = "User updated successfully"
        else:
            r_user.set(key, json.dumps(user_data).encode('utf-8'))
            hooks.call_user_created(user_id, user_data, r_user)
            payload_user = user_data
            msg = "User added successfully"
        if after_user_saved is not None:
            after_user_saved(user_id)
        return {"message": msg, "user": payload_user}

    @app.post("/api/delete_user")
    async def delete_user(user_data: dict):
        """Delete a user by ID"""
        r_user = app.state.redis_user
        user_id = user_data.get("id")
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required")
        key = f"user:{user_id}"
        if not r_user.exists(key):
            raise HTTPException(status_code=404, detail="User not found")
        
        user_info_raw = r_user.get(key)
        user_data_backup = json.loads(user_info_raw) if user_info_raw else user_data
        
        # 调用删除钩子（在删除之前调用，以便清理相关数据）
        hooks.call_user_deleted(user_id, user_data_backup, r_user)

        if before_user_key_deleted is not None:
            before_user_key_deleted(user_id)

        r_user.delete(key)

        # 备份已删除用户数据至 deleted_user 表
        deleted_key = f"user_deleted:{user_id}"
        r_user.set(deleted_key, json.dumps(user_data_backup).encode('utf-8'))

        return {"message": f"User {user_id} deleted successfully"}

    @app.post("/api/change_user_password")
    async def change_user_password(change_request: dict):
        """Change a user's password"""
        r_user = app.state.redis_user
        user_id = change_request.get("id")
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required")
        key = f"user:{user_id}"
        if not r_user.exists(key):
            raise HTTPException(status_code=404, detail="User not found")
        
        user_raw = r_user.get(key)
        user = json.loads(user_raw)
        new_password = change_request.get("password")
        old_password = change_request.get("old_password")
        super_command = change_request.get("super_command")
        
        if not new_password:
            raise HTTPException(status_code=400, detail="New password is required")
        if not old_password:
            raise HTTPException(status_code=400, detail="Old password is required")

        # 如果原本user数据有password字段，则验证旧密码 (可以用 super command 跳过)
        if "password" in user and user["password"] != old_password and super_command != "just do it":
            raise HTTPException(status_code=400, detail="Old password is incorrect")

        user["password"] = new_password
        r_user.set(key, json.dumps(user).encode('utf-8'))

        user_hidding_password = user.copy()
        user_hidding_password.pop("password", None)
        return {"message": "Password changed successfully", "user": user_hidding_password}

    @app.post("/api/login")
    async def login(login_request: dict, response: Response):
        """User login"""
        r_user = app.state.redis_user
        user_id = login_request.get("id")
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required")
        key = f"user:{user_id}"
        if not r_user.exists(key):
            raise HTTPException(status_code=404, detail="User not found")

        user_raw = r_user.get(key)
        user = json.loads(user_raw)
        password = login_request.get("password")
        if not password:
            raise HTTPException(status_code=400, detail="Password is required")

        # 验证密码
        if user.get("password"):
            if user["password"] != password:
                raise HTTPException(status_code=400, detail="Incorrect password")
        elif user.get("srp_verifier"):
            # SRP-only 账号（注册即 SRP / 已 strip 明文）：明文路径无法校验，
            # 必须拒绝——否则没有 password 字段时任意密码都能登录。
            # 409 与 /api/srp/login/challenge 对未迁移用户的语义互为镜像。
            raise HTTPException(
                status_code=409,
                detail="Account uses SRP login; use /api/srp/login/challenge",
            )

        device_name = login_request.get("device_name", "Unknown Device")
        existing_token = issue_or_reuse_access_token(r_user, user_id, device_name)
        _set_sso_cookie(response, existing_token)
        public_user = {k: v for k, v in user.items() if k not in self_userinfo_keys_mask}
        return {"message": "Login successful", "user": public_user, "access_token": existing_token}

    @app.post("/api/validate_login")
    async def validate_login(response: Response, estore_access_token: str = Cookie(None)):
        """Validate user login with cookie token (SSO)"""
        if not estore_access_token:
            raise HTTPException(status_code=401, detail="No access token cookie found")
        
        r_user = app.state.redis_user
        
        # 1. 从 Cookie Token 反查 User ID
        user_id = r_user.get(f"access_token_lookup:{estore_access_token}")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        user_id = user_id.decode("utf-8")
        
        # 2. 验证 Token 是否仍然有效 (check_access_token returns (bool, device_name))
        # 注意：check_access_token 签名是 (token, user_id, redis)
        authed, device_name = check_access_token(estore_access_token, user_id, r_user)
        if not authed:
            raise HTTPException(status_code=403, detail="Token validation failed")

        # 3. 刷新 Token 有效期 (续期)
        token_key = f"access_token:{user_id}:{estore_access_token}"
        if not _is_manual_token(r_user, user_id, estore_access_token):
            r_user.expire(token_key, 30 * 24 * 60 * 60)
            r_user.expire(f"access_token_lookup:{estore_access_token}", 30 * 24 * 60 * 60)

        # 4. 获取用户信息
        key = f"user:{user_id}"
        if not r_user.exists(key):
            raise HTTPException(status_code=404, detail="User not found")
        
        user_raw = r_user.get(key)
        user = json.loads(user_raw)
        return {"message": "Login validated successfully", "user": user, "device_name": device_name}

    @app.get("/api/my_sessions")
    async def my_sessions(authorization: str = Header(None)):
        """
        列出当前账号下全部有效登录会话（Redis access_token）。
        需 Authorization: Bearer <当前 access_token>。
        返回每条含 access_token（供调用方登出该会话）、device_name、expires_in_seconds、is_current。
        """
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization header is required")
        bearer = authorization[7:].strip()
        if not bearer:
            raise HTTPException(status_code=401, detail="Invalid authorization token")
        r_user = app.state.redis_user
        user_id = get_user_id_from_token(bearer, r_user)
        if not user_id:
            raise HTTPException(status_code=403, detail="Invalid access token")
        prefix = f"access_token:{user_id}:"
        raw_keys = r_user.keys(f"{prefix}*")
        sessions = []
        for token_key in raw_keys:
            if not token_key:
                continue
            key_s = token_key.decode("utf-8") if isinstance(token_key, (bytes, bytearray)) else str(token_key)
            parts = key_s.split(":")
            if len(parts) < 3:
                continue
            sess_token = parts[-1]
            val_raw = r_user.get(token_key)
            device_name = val_raw.decode("utf-8") if val_raw else ""
            ttl = r_user.ttl(token_key)
            if ttl is None:
                ttl_sec = 0
            elif ttl == -1:
                ttl_sec = -1  # 显式："永不过期"（手动 token 走 PERSIST 路径）
            elif ttl < 0:
                ttl_sec = 0  # -2: key 不存在 / 已过期
            else:
                ttl_sec = int(ttl)
            meta = _load_token_meta(r_user, user_id, sess_token)
            sessions.append(
                {
                    "access_token": sess_token,
                    "device_name": device_name or "未知设备",
                    "expires_in_seconds": ttl_sec,
                    "is_current": sess_token == bearer,
                    "is_manual": bool(meta.get("is_manual")),
                    "created_at": meta.get("created_at"),
                }
            )
        sessions.sort(key=lambda s: (not s["is_current"], s["device_name"] or ""))
        return {"sessions": sessions}

    @app.post("/api/manual_token")
    async def create_manual_token(payload: dict, authorization: str = Header(None)):
        """
        手动签发一个 access token，用于脚本/CI 等需要长期或自定义 TTL 的场景。

        鉴权：Authorization: Bearer <调用方当前 token>。新 token 归属同一 user_id。

        请求体：
          - device_name (str, 必填)：展示用名称，与登录路径的 device_name 同字段
          - ttl_seconds (int | None)：自定义有效期；缺省/小于等于 0 视为 None=永不过期

        返回：access_token（**只在此处返回一次**，请妥善保存）、device_name、
              expires_in_seconds（永不过期为 -1）、is_manual=True、created_at。
        """
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization header is required")
        bearer = authorization[7:].strip()
        if not bearer:
            raise HTTPException(status_code=401, detail="Invalid authorization token")
        r_user = app.state.redis_user
        user_id = get_user_id_from_token(bearer, r_user)
        if not user_id:
            raise HTTPException(status_code=403, detail="Invalid access token")

        device_name = (payload.get("device_name") or "").strip()
        if not device_name:
            raise HTTPException(status_code=400, detail="device_name is required")

        ttl_raw = payload.get("ttl_seconds")
        if ttl_raw is None or (isinstance(ttl_raw, (int, float)) and ttl_raw <= 0):
            ttl_seconds: Optional[int] = None  # 永不过期
        else:
            try:
                ttl_seconds = int(ttl_raw)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="ttl_seconds must be an integer")
            if ttl_seconds <= 0:
                ttl_seconds = None

        new_token = uuid.uuid4().hex
        token_key = f"access_token:{user_id}:{new_token}"
        if ttl_seconds is None:
            r_user.set(token_key, device_name.encode("utf-8"))
        else:
            r_user.set(token_key, device_name.encode("utf-8"), ex=ttl_seconds)

        created_at = int(time.time())
        _save_token_meta(
            r_user,
            user_id,
            new_token,
            {"is_manual": True, "created_at": created_at},
            ttl_seconds,
        )

        return {
            "access_token": new_token,
            "device_name": device_name,
            "expires_in_seconds": -1 if ttl_seconds is None else ttl_seconds,
            "is_manual": True,
            "created_at": created_at,
        }

    @app.post("/api/logout")
    async def logout(
        response: Response,
        logout_request: Optional[dict] = Body(default=None),
        authorization: str = Header(None),
        estore_access_token: Optional[str] = Cookie(None),
    ):
        """Logout user from a specific device"""
        r_user = app.state.redis_user
        logout_request = logout_request or {}

        # access token：优先 body，其次 Bearer header，最后 SSO cookie
        access_token = logout_request.get("access_token")
        if not access_token and authorization and authorization.startswith("Bearer "):
            access_token = authorization[7:].strip()
        if not access_token and estore_access_token:
            access_token = estore_access_token
        if not access_token:
            raise HTTPException(status_code=400, detail="Access token is required")

        user_id = logout_request.get("id") or get_user_id_from_token(access_token, r_user)
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required")
        key = f"user:{user_id}"
        if not r_user.exists(key):
            raise HTTPException(status_code=404, detail="User not found")

        # 检查权限
        authed, device_name = check_access_token(access_token, user_id, r_user)

        if not authed:
            raise HTTPException(status_code=403, detail="Invalid access token")

        # 删除对应的 access token 与其 meta
        token_key = f"access_token:{user_id}:{access_token}"
        if r_user.exists(token_key):
            r_user.delete(token_key)
            _delete_token_meta(r_user, user_id, access_token)
            _clear_sso_cookie(response)
            print(f"User {user_id} logged out from device {device_name}.")
            return {"message": "Logged out successfully"}

        raise HTTPException(status_code=404, detail="Access token not found")

    @app.post("/api/logout_all_devices")
    async def logout_all_devices(logout_request: dict):
        """Logout user from all devices"""
        r_user = app.state.redis_user
        user_id = logout_request.get("id")
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required")
        key = f"user:{user_id}"
        if not r_user.exists(key):
            raise HTTPException(status_code=404, detail="User not found")

        # 检查权限
        access_token = logout_request.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Access token is required")
        authed, device_name = check_access_token(access_token, user_id, r_user)

        if not authed:
            raise HTTPException(status_code=403, detail="Invalid access token")

        # 删除所有 access token 与其 meta
        all_tokens_records = r_user.keys(f"access_token:{user_id}:*")
        for token_key in all_tokens_records:
            r_user.delete(token_key)
        all_meta_records = r_user.keys(f"access_token_meta:{user_id}:*")
        for meta_key in all_meta_records:
            r_user.delete(meta_key)

        print(f"User {user_id} logged out all devices (from device {device_name}).")

        return {"message": "Logged out from all devices successfully"}

    if _avatar_file_to_url is None:
        # 既没注入 file_to_url，也没找到内置 cos_upload —— 不注册头像 API。
        # 调用方若需要头像功能，请显式传入 file_to_url=flow_upload.file_to_url。
        pass
    else:
        @app.post("/api/upload_avatar")
        async def upload_avatar_api(
            file: UploadFile = File(...),
            user_id: str = Depends(get_current_user_id_dep),
        ):
            """
            上传用户头像到腾讯云 COS。bucket 优先 register_user_apis 的 avatar_bucket
            参数；其次模块级 USER_SYSTEM_COS_BUCKET（来自宿主 config.py 或默认值）。
            上传函数为 register_user_apis 注入的 file_to_url（推荐 flow_upload.file_to_url）。
            前端已处理图片格式转换和文件重命名。

            身份验证走 get_current_user_id_dep（Depends 注入）：优先
            Authorization: Bearer header，缺失时回退跨子域 SSO Cookie
            （estore_access_token）。此前手动调用该依赖只传了 header，
            导致仅持 SSO Cookie 登录态的用户（如平台管理员）上传头像 401。

            参数:
              file: 要上传的头像文件（前端已转换为PNG格式并以用户ID命名）

            返回:
              上传后的文件 URL
            """
            try:
                # 直接使用前端传来的文件（已重命名为用户ID）
                file_url = _avatar_file_to_url(
                    file, folder_name=avatar_folder, bucket=_avatar_bucket
                )

                return {
                    "status": "success",
                    "message": "Avatar uploaded successfully",
                    "file_url": file_url,
                    "filename": file.filename
                }
            except HTTPException:
                raise
            except Exception as e:
                return JSONResponse(
                    status_code=500,
                    content={
                        "status": "error",
                        "message": f"Failed to upload avatar: {str(e)}"
                    }
                )

    # 挂上 SRP 路由（/api/srp/...）。与旧的 /api/login 等明文路径并存，
    # 由前端 SDK 选择走哪条；待迁移完成后再删除明文路径。
    register_srp_apis(
        app,
        get_user_redis=get_user_redis,
        get_user_id_from_token=get_user_id_from_token,
        issue_access_token=issue_or_reuse_access_token,
        set_sso_cookie=_set_sso_cookie,
    )

    # 返回依赖函数供外部使用
    return get_current_user_id_dep

