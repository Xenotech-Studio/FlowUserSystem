"""
腾讯云 COS 文件上传工具
提供通用的文件上传功能，供用户系统和其他模块使用。
密钥：优先从 config.TENCENT_SECRET_ID / TENCENT_SECRET_KEY 读取，否则使用下方默认（与联网搜索等腾讯云 API 共用）。
"""

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
    config = CosConfig(Region=region, SecretId=secret_id, SecretKey=secret_key, Scheme=scheme)
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

