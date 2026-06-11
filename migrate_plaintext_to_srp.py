"""一次性脚本：把 user:{id} 里的明文 password 字段转成 SRP verifier + envelope。

使用前必读：
  - 这脚本会读所有 user:* 键，对每条记录:
    1. 已有 srp_verifier → 跳过（除非 --force）
    2. 没有 password 字段 → 跳过（社交登录用户）
    3. 有 password 但没 srp_verifier → 生成 salt + verifier + envelope 写回
  - 默认会保留旧 password 字段，让老前端在迁移窗口里继续能登
  - --strip-plaintext 才会把 password 字段从记录里抹掉（最终清理用）

用法:
  python -m backend.user_system.migrate_plaintext_to_srp --dry-run
  python -m backend.user_system.migrate_plaintext_to_srp                  # 真写
  python -m backend.user_system.migrate_plaintext_to_srp --strip-plaintext
  python -m backend.user_system.migrate_plaintext_to_srp --redis-db 9     # 跑测试库
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import redis

from .srp_apis import generate_srp_credentials


def _load_redis(host: str, port: int, db: int) -> redis.Redis:
    return redis.Redis(host=host, port=port, db=db, decode_responses=False)


def migrate(
    r: redis.Redis,
    *,
    dry_run: bool = False,
    force: bool = False,
    strip_plaintext: bool = False,
) -> dict:
    stats = {"total": 0, "migrated": 0, "skipped_no_password": 0,
             "skipped_already_migrated": 0, "errors": 0}

    for key in r.scan_iter(match="user:*", count=200):
        stats["total"] += 1
        raw = r.get(key)
        if not raw:
            continue
        try:
            user = json.loads(raw)
        except Exception as e:
            print(f"  [ERR] {key!r}: bad JSON ({e})", file=sys.stderr)
            stats["errors"] += 1
            continue

        user_id = user.get("id") or key.decode("utf-8").split(":", 1)[1]
        has_plaintext = "password" in user and user["password"]
        has_srp = bool(user.get("srp_verifier")) and bool(user.get("srp_salt"))

        if has_srp and not force:
            stats["skipped_already_migrated"] += 1
            if strip_plaintext and has_plaintext:
                user.pop("password", None)
                if not dry_run:
                    r.set(key, json.dumps(user).encode("utf-8"))
                print(f"  [STRIP] {user_id}: removed lingering password field")
            continue

        if not has_plaintext:
            stats["skipped_no_password"] = stats["skipped_no_password"] + 1
            continue

        plaintext = user["password"]
        try:
            creds = generate_srp_credentials(user_id, plaintext)
        except Exception as e:
            print(f"  [ERR] {user_id}: derive failed ({e})", file=sys.stderr)
            stats["errors"] += 1
            continue

        user.update(creds)
        if strip_plaintext:
            user.pop("password", None)

        if dry_run:
            print(f"  [DRY] {user_id}: would migrate "
                  f"(salt={creds['srp_salt'][:8]}..., verifier_len={len(creds['srp_verifier'])},"
                  f" env_len={len(creds['password_envelope'])})")
        else:
            r.set(key, json.dumps(user).encode("utf-8"))
            print(f"  [OK]  {user_id}: migrated"
                  + (" + plaintext stripped" if strip_plaintext else ""))
        stats["migrated"] += 1

    return stats


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-host", default=os.getenv("FLOWSYS_REDIS_HOST", "127.0.0.1"))
    parser.add_argument("--redis-port", type=int, default=int(os.getenv("FLOWSYS_REDIS_PORT", "6379")))
    parser.add_argument("--redis-db", type=int, default=int(os.getenv("FLOWSYS_REDIS_DB", "7")))
    parser.add_argument("--dry-run", action="store_true", help="只打印将要做什么，不写库")
    parser.add_argument("--force", action="store_true", help="即使已有 srp_verifier 也重新生成")
    parser.add_argument("--strip-plaintext", action="store_true",
                        help="把 password 字段从记录中抹掉（最终清理用）")
    args = parser.parse_args(argv)

    print(f"target redis: {args.redis_host}:{args.redis_port} db={args.redis_db}"
          f" dry_run={args.dry_run} force={args.force} strip={args.strip_plaintext}")
    r = _load_redis(args.redis_host, args.redis_port, args.redis_db)
    stats = migrate(r, dry_run=args.dry_run, force=args.force,
                    strip_plaintext=args.strip_plaintext)
    print("\n=== summary ===")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    return 0 if stats["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
