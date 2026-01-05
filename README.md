# 用户系统模块 (User System Module)

这是一个独立的用户系统模块，提供用户管理、认证、文件上传等功能。

## 目录结构

```
user_system/
├── __init__.py          # 模块导出
├── user_apis.py         # 用户 API 路由和业务逻辑
├── hooks.py             # Hook 机制，支持扩展
├── cos_upload.py        # 腾讯云 COS 文件上传工具
└── README.md           # 本文件
```

## 功能特性

- ✅ 用户信息管理（CRUD）
- ✅ 用户认证（登录、登出、验证）
- ✅ 密码管理
- ✅ 头像上传
- ✅ 多设备登录支持
- ✅ Hook 机制支持业务扩展
- ✅ 腾讯云 COS 文件上传（可被其他模块复用）

## 使用方法

### 基本使用

```python
from fastapi import FastAPI
from user_system import register_user_apis

app = FastAPI()

# 注册用户系统 API
register_user_apis(app)
```

### 使用 Hook 扩展功能

```python
from fastapi import FastAPI
from user_system import register_user_apis, UserHooks
import redis

def on_user_created(user_id: str, user_data: dict, redis_client: redis.Redis):
    """用户创建时的回调"""
    # 例如：自动创建个人项目
    personal_project_id = f"{user_id}_personal"
    # ... 创建项目的逻辑

def on_user_deleted(user_id: str, user_data: dict, redis_client: redis.Redis):
    """用户删除时的回调"""
    # 例如：清理用户相关数据
    # ... 清理逻辑

app = FastAPI()

# 创建 Hook 实例
hooks = UserHooks(
    on_user_created=on_user_created,
    on_user_deleted=on_user_deleted
)

# 注册用户系统 API（带 Hook）
register_user_apis(app, hooks=hooks)
```

### 在其他模块中使用文件上传功能

```python
from user_system import file_to_url
from fastapi import UploadFile, File

@app.post("/api/upload_file")
async def upload_file(file: UploadFile = File(...)):
    # 基本使用：使用默认 bucket
    file_url = file_to_url(file, folder_name="MY_FOLDER")
    return {"url": file_url}

@app.post("/api/upload_file_custom")
async def upload_file_custom(file: UploadFile = File(...)):
    # 指定 bucket
    file_url = file_to_url(file, folder_name="MY_FOLDER", bucket="my-bucket")
    return {"url": file_url}

@app.post("/api/upload_file_advanced")
async def upload_file_advanced(file: UploadFile = File(...)):
    # 高级功能：自定义存储文件名和下载文件名
    file_url = file_to_url(
        file, 
        folder_name="MY_FOLDER", 
        bucket="my-bucket",
        cos_filename="custom_stored_name.jpg",  # COS中存储的文件名
        download_filename="original_name.jpg"     # 浏览器下载时显示的文件名
    )
    return {"url": file_url}
```

**参数说明：**
- `file`: UploadFile 对象（必需）
- `folder_name`: 目标文件夹名称（可选，默认为空）
- `bucket`: COS bucket 名称（可选，默认为 "flowtask-1302933783"）
- `cos_filename`: COS中存储的文件名（可选，如果提供则使用此名称，否则使用原始文件名）
- `download_filename`: 下载时展示的文件名（可选，设置后会添加 Content-Disposition 头）

### 获取当前用户ID（用于需要认证的 API）

```python
from fastapi import Depends
from user_system import create_get_current_user_id_dependency

app = FastAPI()
register_user_apis(app)

# 创建依赖函数
get_current_user_id = create_get_current_user_id_dependency(app)

@app.get("/api/protected")
async def protected_endpoint(user_id: str = Depends(get_current_user_id)):
    return {"user_id": user_id}
```

## API 端点

### 用户管理
- `GET /api/users` - 获取所有用户
- `GET /api/user/{user_id}` - 获取单个用户
- `POST /api/user` - 创建或更新用户
- `POST /api/delete_user` - 删除用户

### 认证
- `POST /api/login` - 用户登录
- `GET /api/validate_login` - 验证登录状态
- `POST /api/logout` - 登出当前设备
- `POST /api/logout_all_devices` - 登出所有设备

### 密码管理
- `POST /api/change_user_password` - 修改密码

### 头像上传
- `POST /api/upload_avatar` - 上传用户头像

## 配置

模块使用硬编码的 Redis 配置：
- Host: `127.0.0.1`
- Port: `6379`
- Database: `7` (用户系统数据库)

## 数据结构

### Redis 键结构
- `user:{user_id}` → JSON 用户对象
- `user_deleted:{user_id}` → JSON（被删除用户的快照）
- `access_token:{user_id}:{token}` → String deviceName（TTL=30天）

### 用户信息字段
- 访客可见：`["id", "nickname", "avatarUrl"]`
- 自己可见：除 `password` 外的所有字段

## 作为 Git Submodule

此模块设计为可独立作为 Git submodule 使用：

```bash
# 在其他项目中添加为 submodule
git submodule add <repository-url> user_system
```

然后在代码中导入：
```python
from user_system import register_user_apis
```

## 注意事项

1. 模块使用同步 Redis 客户端（`redis.Redis`）
2. 密码目前以明文存储（未加密）
3. Token 有效期为 30 天，每次验证会自动刷新
4. 支持多设备登录，每个设备一个独立的 token

