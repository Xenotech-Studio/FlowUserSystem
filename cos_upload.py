"""
腾讯云 COS 文件上传工具
提供通用的文件上传功能，供用户系统和其他模块使用。
密钥：优先从 config.TENCENT_SECRET_ID / TENCENT_SECRET_KEY 读取，否则使用下方默认（与联网搜索等腾讯云 API 共用）。
"""

from __future__ import annotations

from io import BytesIO
from queue import Queue
from typing import Any, Callable, List, Optional, Tuple

from qcloud_cos import CosConfig, CosS3Client
import logging
import sys

# 默认密钥（与 COS / 联网搜索等腾讯云 API 共用；建议在 config.py 中配置 TENCENT_SECRET_ID / TENCENT_SECRET_KEY）
_DEFAULT_SECRET_ID = "***REDACTED***"
_DEFAULT_SECRET_KEY = "***REDACTED***"


def get_tencent_credentials():
    """返回 (secret_id, secret_key)，供 COS、联网搜索等腾讯云 API 共用。优先 config，否则默认值。"""
    try:
        import config as _config
        sid = getattr(_config, "TENCENT_SECRET_ID", None) or ""
        sk = getattr(_config, "TENCENT_SECRET_KEY", None) or ""
        if sid.strip() and sk.strip():
            return sid.strip(), sk.strip()
    except ImportError:
        pass
    return _DEFAULT_SECRET_ID, _DEFAULT_SECRET_KEY


class _CosUploadCountingReader:
    """包装 BytesIO：COS SDK 每次 read 后回调 (bytes_consumed, total)，用于上报上传进度。"""

    def __init__(self, data: bytes, on_read: Callable[[int, int], None]) -> None:
        self._io = BytesIO(data)
        self._on_read = on_read
        self._total = len(data)

    def read(self, amt: int = -1) -> bytes:
        b = self._io.read(amt)
        if b:
            self._on_read(self._io.tell(), self._total)
        return b

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._io.seek(pos, whence)


def file_to_url(file, folder_name="", bucket="flowtask-1302933783", cos_filename=None, download_filename=None):
    """
    上传文件到腾讯云 COS
    
    参数：
      file: UploadFile 对象，包含文件名及文件流
      folder_name: 上传的目标子文件夹，可选
      bucket: COS bucket 名称，默认为 "flowtask-1302933783"
      cos_filename: COS中存储的文件名（可选，如果提供则使用此名称，否则使用原始文件名）
      download_filename: 下载时展示的文件名（可选，设置后会添加 Content-Disposition 头，让浏览器下载时显示指定文件名）
    返回值：
      上传后的文件 URL
    """
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    secret_id, secret_key = get_tencent_credentials()
    region = "ap-guangzhou"
    scheme = 'https'
    # 显式禁用代理：与 arXiv 等出站代理分离，避免进程环境变量 HTTPS_PROXY 让 COS 误走代理
    config = CosConfig(
        Region=region,
        SecretId=secret_id,
        SecretKey=secret_key,
        Scheme=scheme,
        Proxies={},
    )
    client = CosS3Client(config)

    # 处理文件夹名称，确保以 "/" 结尾（如果传入非空）
    folder = folder_name + "/" if (folder_name and not folder_name.endswith("/")) else folder_name
    
    # 如果提供了cos_filename，使用它；否则使用原始文件名
    if cos_filename:
        file_name = cos_filename
    else:
        # 使用 UploadFile 的 filename 属性
        file_name = file.filename
        file_name = file_name.split('/')[-1]  # 仅保留文件名部分
    
    # key = 'IMAGES/' + folder + file_name
    key = folder + file_name

    # 构造图片 URL（使用 sdk 的 uri 方法）
    image_url = config.uri(bucket=bucket, path=key)

    # Content-Disposition 让浏览器下载时显示指定文件名
    content_disposition = None
    if download_filename:
        # 防止包含路径，只保留名称
        dl_name = download_filename.split('/')[-1]
        content_disposition = f'attachment; filename="{dl_name}"'

    # 准备上传参数
    upload_params = {
        'Bucket': bucket,
        'Body': file.file,
        'Key': key,
        'StorageClass': 'STANDARD',
        'EnableMD5': False
    }
    
    # 如果设置了 download_filename，添加 ContentDisposition
    if content_disposition:
        upload_params['ContentDisposition'] = content_disposition

    # 使用文件的 file 属性直接获取文件流上传
    response = client.put_object(**upload_params)
    logging.info("Image uploaded to COS: %s", image_url)
    return image_url


def bytes_to_cos_url(
    body: bytes,
    *,
    folder_name: str = "",
    object_name: str = "file.bin",
    bucket: str = "flowtask-1302933783",
    content_type: Optional[str] = None,
    on_body_read_progress: Optional[Callable[[int, int], None]] = None,
) -> str:
    """
    将内存中的字节上传到 COS，返回公网 HTTPS URL（与 file_to_url 同桶、同地域、同鉴权）。

    用于服务端生成可给执行端直连下载的链接（例如技能包 zip 缓存）。
    on_body_read_progress：可选；COS SDK 从 Body 读取时回调 (已读字节, 总字节)。
    """
    secret_id, secret_key = get_tencent_credentials()
    region = "ap-guangzhou"
    scheme = "https"
    # 与 file_to_url 一致：避免环境变量代理影响 COS
    cfg = CosConfig(
        Region=region,
        SecretId=secret_id,
        SecretKey=secret_key,
        Scheme=scheme,
        Proxies={},
    )
    client = CosS3Client(cfg)

    folder = folder_name + "/" if (folder_name and not folder_name.endswith("/")) else folder_name
    safe_name = (object_name or "file.bin").split("/")[-1]
    key = folder + safe_name
    image_url = cfg.uri(bucket=bucket, path=key)

    body_stream: object = BytesIO(body)
    if on_body_read_progress is not None:
        body_stream = _CosUploadCountingReader(body, on_body_read_progress)
    upload_params: dict = {
        "Bucket": bucket,
        "Body": body_stream,
        "Key": key,
        "StorageClass": "STANDARD",
        "EnableMD5": False,
    }
    if content_type and str(content_type).strip():
        upload_params["ContentType"] = str(content_type).strip()

    client.put_object(**upload_params)
    logging.info("Bytes uploaded to COS: %s", image_url)
    return image_url


def multipart_upload_from_chunk_queue(
    q: "Queue[Tuple[str, Any]]",
    *,
    folder_name: str = "",
    object_name: str = "file.bin",
    bucket: str = "flowtask-1302933783",
    content_type: Optional[str] = None,
    on_cos_bytes: Optional[Callable[[int], None]] = None,
    part_size: int = 5 * 1024 * 1024,
) -> str:
    """
    从队列拉取 (\"data\", chunk) / (\"end\", None) / (\"err\", msg)，边收边 multipart 上传到 COS。
    单 part 最小 part_size（末 part 可更小）；空文件走 put_object。
    """
    secret_id, secret_key = get_tencent_credentials()
    region = "ap-guangzhou"
    scheme = "https"
    cfg = CosConfig(
        Region=region,
        SecretId=secret_id,
        SecretKey=secret_key,
        Scheme=scheme,
        Proxies={},
    )
    client = CosS3Client(cfg)

    folder = folder_name + "/" if (folder_name and not folder_name.endswith("/")) else folder_name
    safe_name = (object_name or "file.bin").split("/")[-1]
    key = folder + safe_name
    image_url = cfg.uri(bucket=bucket, path=key)

    buffer = bytearray()
    uploaded = 0
    upload_id: Optional[str] = None
    parts: List[dict] = []
    part_number = 1

    def _report_cos() -> None:
        """已确认上传的字节 + 仍待 upload_part 的缓冲，单调递增；避免 < part_size 时长期不报导致进度条卡在 0。"""
        if on_cos_bytes is not None:
            on_cos_bytes(int(uploaded) + len(buffer))

    def _flush(force: bool = False) -> None:
        nonlocal buffer, uploaded, part_number, parts
        while len(buffer) >= part_size or (force and buffer):
            take = len(buffer) if force else part_size
            if take <= 0:
                break
            body = bytes(buffer[:take])
            del buffer[:take]
            if not upload_id:
                raise RuntimeError("multipart_upload_from_chunk_queue: internal state error (no upload_id)")
            up = client.upload_part(
                Bucket=bucket,
                Key=key,
                PartNumber=part_number,
                UploadId=upload_id,
                Body=body,
            )
            etag_raw = up.get("ETag") or ""
            etag = str(etag_raw).strip().strip('"')
            parts.append({"PartNumber": part_number, "ETag": etag})
            part_number += 1
            uploaded += len(body)
            _report_cos()

    try:
        while True:
            kind, payload = q.get()
            if kind == "err":
                raise ValueError(str(payload) if payload is not None else "upload aborted")
            if kind == "end":
                break
            if kind != "data":
                continue
            chunk = payload if isinstance(payload, (bytes, bytearray)) else bytes(payload)
            if not chunk:
                continue
            if upload_id is None:
                extra: dict = {"Bucket": bucket, "Key": key}
                if content_type and str(content_type).strip():
                    extra["ContentType"] = str(content_type).strip()
                cre = client.create_multipart_upload(**extra)
                upload_id = cre.get("UploadId")
                if not upload_id:
                    raise RuntimeError("create_multipart_upload missing UploadId")
            buffer.extend(chunk)
            _flush(force=False)
            _report_cos()

        if upload_id is None:
            if buffer:
                extra_put: dict = {
                    "Bucket": bucket,
                    "Key": key,
                    "Body": bytes(buffer),
                    "StorageClass": "STANDARD",
                    "EnableMD5": False,
                }
                if content_type and str(content_type).strip():
                    extra_put["ContentType"] = str(content_type).strip()
                client.put_object(**extra_put)
                n = len(buffer)
                buffer.clear()
                uploaded = n
                _report_cos()
            else:
                extra_put = {
                    "Bucket": bucket,
                    "Key": key,
                    "Body": b"",
                    "StorageClass": "STANDARD",
                    "EnableMD5": False,
                }
                if content_type and str(content_type).strip():
                    extra_put["ContentType"] = str(content_type).strip()
                client.put_object(**extra_put)
                uploaded = 0
                _report_cos()
            logging.info("Stream uploaded to COS (put_object): %s", image_url)
            return image_url

        _flush(force=True)
        _report_cos()
        if not parts:
            client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
            raise RuntimeError("multipart upload: no parts")

        parts_sorted = sorted(parts, key=lambda x: int(x["PartNumber"]))
        # 腾讯云 qcloud_cos 的 dict_to_xml 要求键名为 Part（列表），用 Parts 会得到「Part Is Required」
        client.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Part": parts_sorted},
        )
        logging.info("Stream uploaded to COS (multipart): %s", image_url)
        return image_url
    except Exception:
        if upload_id:
            try:
                client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
            except Exception:
                pass
        raise

