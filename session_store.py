"""SessionStore —— SRP 鉴权层的存储边界（user_system 自有协议）。

本 submodule 被 5 个 server 共享，**不依赖任何宿主包**：路由只认这个 Protocol，
宿主产品把自己的实现注入 ``register_srp_apis(app, store=...)``（如 Flops 主仓库的
``RedisSessionStore``：Redis 主写 + SQLite 双写）。结构化类型（Protocol）意味着
宿主实现无需继承本类 —— 方法签名对上即可。

存储面（与 SRP 路由今日所做的完全一致）：
- 用户记录：``get_user`` / ``save_user``（``user:{id}`` JSON blob）
- SRP challenge：``put_challenge``（带 TTL）/ ``take_challenge``（原子一次性）
- token：``issue_access_token`` / ``resolve_user_id``
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class SessionStore(Protocol):
    """SRP 鉴权层的存储边界。方法均为同步（路由 async，存储操作是快速 Redis 往返）。"""

    # ---- 用户记录 --------------------------------------------------------
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """返回 ``user:{user_id}`` 记录 dict；不存在返回 None。"""
        ...

    def save_user(self, user: Dict[str, Any]) -> None:
        """持久化（已就地修改的）用户记录；实现方保持宿主自己的写路径语义。"""
        ...

    # ---- SRP challenge（一次性、带 TTL）---------------------------------
    def put_challenge(self, session_id: str, data: Dict[str, Any], ttl_sec: int) -> None:
        """以 ``session_id`` 存一条登录/改密 challenge（带 TTL，覆盖写）。"""
        ...

    def take_challenge(self, session_id: str) -> Optional[Dict[str, Any]]:
        """原子读取并删除 challenge（重放保护）；缺失/过期返回 None。"""
        ...

    # ---- access token ----------------------------------------------------
    def issue_access_token(self, user_id: str, device_name: str) -> str:
        """为用户签发（或按宿主策略复用）一个 access token。"""
        ...

    def resolve_user_id(self, token: str) -> Optional[str]:
        """bearer token → user_id；无效/过期返回 None。"""
        ...


__all__ = ["SessionStore"]
