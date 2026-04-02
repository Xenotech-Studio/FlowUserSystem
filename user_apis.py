"""
User APIs
用户相关的所有 API 路由定义和业务逻辑

本文件包含用户系统相关的所有 API，包括：
- 用户信息管理（获取、创建、更新、删除）
- 用户认证（登录、登出、验证）
- 密码管理（修改密码）
- 头像上传
"""

from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Depends
from fastapi.responses import JSONResponse
from typing import Optional
import json
import uuid
import redis
import os
from .cos_upload import file_to_url

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

# Redis 默认连接配置（可被 init_user_redis 参数覆盖）
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_USER_DB = 7  # 用户系统 Redis 数据库编号

# 用户信息字段配置
visitor_userinfo_keys = ["id", "nickname", "avatarUrl"]
self_userinfo_keys_mask = ["password"]

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
    def _get_current_user_id(authorization: str = Header(None)) -> str:
        """从请求头获取当前用户ID"""
        if not authorization:
            raise HTTPException(status_code=401, detail="Authorization header is required")
        
        # 提取Bearer token
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization format")
        
        token = authorization[7:]  # 移除 "Bearer " 前缀
        
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
):
    """
    注册所有用户相关的 API 路由和数据库初始化
    
    参数:
      app: FastAPI 应用实例
      hooks: 可选的用户操作钩子，用于在用户创建/更新/删除时执行自定义逻辑
      register_redis_init: 若为 False，则不再注册 init_user_redis（适用于已在别处调用过 init_user_redis 的场景）
      redis_host/redis_port/redis_db: 用户系统 Redis 覆盖配置
    
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
        from apis.estore_b_identity import ensure_manager_extension_if_missing

        ensure_manager_extension_if_missing(user_id)
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

        from apis.estore_b_identity import delete_manager_extension_for_flow_user

        delete_manager_extension_for_flow_user(user_id)

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
    async def login(login_request: dict):
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
        if "password" in user and user["password"] != password:
            raise HTTPException(status_code=400, detail="Incorrect password")

        # 获取 Device Name (尽量确保 Device Name 独特)
        device_name = login_request.get("device_name", "Unknown Device")

        # 检查是否有 access token 对应该设备
        existing_token = None
        all_tokens_records = r_user.keys(f"access_token:{user_id}:*")
        for token_key in all_tokens_records:
            token_value_raw = r_user.get(token_key)
            if token_value_raw:
                token_value = token_value_raw.decode('utf-8')
                if token_value == device_name:
                    # 如果找到匹配的 access token，直接返回
                    existing_token = token_key.decode('utf-8').split(":")[-1]
                    # 刷新 access token 的有效期
                    r_user.expire(token_key, 30 * 24 * 60 * 60)  # 设置有效期为 30 天

        # 如果没有找到匹配的 access token，则创建一个新的
        if not existing_token:
            # 创建 access token 用 uuid
            new_access_token = uuid.uuid4().hex
            new_access_token_key = f"access_token:{user_id}:{new_access_token}"
            # 设置 access token 有效期为 30 天
            r_user.set(new_access_token_key, device_name.encode('utf-8'), ex=30 * 24 * 60 * 60)
            existing_token = new_access_token

        return {"message": "Login successful", "user": user, "access_token": existing_token}

    @app.get("/api/validate_login")
    async def validate_login(user_id: str, access_token: str):
        """Validate user login with access token"""
        r_user = app.state.redis_user
        if not user_id or not access_token:
            raise HTTPException(status_code=400, detail="User ID and access token are required")
        
        authed, device_name = check_access_token(access_token, user_id, r_user)
        if not authed:
            raise HTTPException(status_code=403, detail="Invalid access token")

        #更新 access token 的有效期
        token_key = f"access_token:{user_id}:{access_token}"
        r_user.expire(token_key, 30 * 24 * 60 * 60)  # 设置有效期为 30 天

        # 获取用户信息
        key = f"user:{user_id}"
        if not r_user.exists(key):
            raise HTTPException(status_code=404, detail="User not found")
        
        user_raw = r_user.get(key)
        user = json.loads(user_raw)
        return {"message": "Login validated successfully", "user": user, "device_name": device_name}

    @app.post("/api/logout")
    async def logout(logout_request: dict):
        """Logout user from a specific device"""
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

        # 删除对应的 access token
        token_key = f"access_token:{user_id}:{access_token}"
        if r_user.exists(token_key):
            r_user.delete(token_key)
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

        # 删除所有 access token
        all_tokens_records = r_user.keys(f"access_token:{user_id}:*")
        for token_key in all_tokens_records:
            r_user.delete(token_key)

        print(f"User {user_id} logged out all devices (from device {device_name}).")

        return {"message": "Logged out from all devices successfully"}

    @app.post("/api/upload_avatar")
    async def upload_avatar_api(
        file: UploadFile = File(...),
        authorization: str = Header(None)
    ):
        """
        上传用户头像到腾讯云 COS（bucket 优先 config.USER_SYSTEM_COS_BUCKET，否则与 cos_upload 默认 bucket 相同）
        前端已处理图片格式转换和文件重命名
        
        参数:
          file: 要上传的头像文件（前端已转换为PNG格式并以用户ID命名）
          authorization: Bearer token，用于身份验证
        
        返回:
          上传后的文件 URL
        """
        try:
            # 验证用户身份
            if not authorization:
                raise HTTPException(status_code=401, detail="Authorization header is required")
            
            r_user = app.state.redis_user
            user_id = get_current_user_id_dep(authorization)
            if not user_id:
                raise HTTPException(status_code=403, detail="Invalid access token")
            
            # 直接使用前端传来的文件（已重命名为用户ID）
            file_url = file_to_url(
                file, folder_name="AVATARS", bucket=USER_SYSTEM_COS_BUCKET
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
    
    # 返回依赖函数供外部使用
    return get_current_user_id_dep

