"""
用户系统 Hook 机制
允许外部在用户操作时执行自定义逻辑
"""

from typing import Optional, Callable, Dict, Any
import redis

class UserHooks:
    """用户系统回调钩子"""
    
    def __init__(
        self,
        on_user_created: Optional[Callable[[str, Dict[str, Any], redis.Redis], None]] = None,
        on_user_updated: Optional[Callable[[str, Dict[str, Any], redis.Redis], None]] = None,
        on_user_deleted: Optional[Callable[[str, Dict[str, Any], redis.Redis], None]] = None,
    ):
        """
        初始化用户系统钩子
        
        参数:
          on_user_created: 用户创建时的回调函数 (user_id, user_data, redis_client) -> None
          on_user_updated: 用户更新时的回调函数 (user_id, user_data, redis_client) -> None
          on_user_deleted: 用户删除时的回调函数 (user_id, user_data, redis_client) -> None
        """
        self.on_user_created = on_user_created
        self.on_user_updated = on_user_updated
        self.on_user_deleted = on_user_deleted
    
    def call_user_created(self, user_id: str, user_data: Dict[str, Any], redis_client: redis.Redis):
        """调用用户创建回调"""
        if self.on_user_created:
            try:
                self.on_user_created(user_id, user_data, redis_client)
            except Exception as e:
                print(f"Error in on_user_created hook: {e}")
    
    def call_user_updated(self, user_id: str, user_data: Dict[str, Any], redis_client: redis.Redis):
        """调用用户更新回调"""
        if self.on_user_updated:
            try:
                self.on_user_updated(user_id, user_data, redis_client)
            except Exception as e:
                print(f"Error in on_user_updated hook: {e}")
    
    def call_user_deleted(self, user_id: str, user_data: Dict[str, Any], redis_client: redis.Redis):
        """调用用户删除回调"""
        if self.on_user_deleted:
            try:
                self.on_user_deleted(user_id, user_data, redis_client)
            except Exception as e:
                print(f"Error in on_user_deleted hook: {e}")

