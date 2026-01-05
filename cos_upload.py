"""
腾讯云 COS 文件上传工具
提供通用的文件上传功能，供用户系统和其他模块使用
"""

from qcloud_cos import CosConfig, CosS3Client
import logging
import sys

def file_to_url(file, folder_name="", bucket="flowtask-1302933783"):
    """
    上传文件到腾讯云 COS
    
    参数：
      file: UploadFile 对象，包含文件名及文件流
      folder_name: 上传的目标子文件夹，可选
      bucket: COS bucket 名称，默认为 "flowtask-1302933783"
    返回值：
      上传后的文件 URL
    """
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    secret_id = '***REDACTED***'
    secret_key = '***REDACTED***'
    region = 'ap-guangzhou'
    scheme = 'https'
    config = CosConfig(Region=region, SecretId=secret_id, SecretKey=secret_key, Scheme=scheme)
    client = CosS3Client(config)

    # 处理文件夹名称，确保以 "/" 结尾（如果传入非空）
    folder = folder_name + "/" if (folder_name and not folder_name.endswith("/")) else folder_name
    # 使用 UploadFile 的 filename 属性
    file_name = file.filename
    file_name = file_name.split('/')[-1]  # 仅保留文件名部分
    
    # key = 'IMAGES/' + folder + file_name
    key = folder + file_name

    # 构造图片 URL（使用 sdk 的 uri 方法）
    image_url = config.uri(bucket=bucket, path=key)

    # 使用文件的 file 属性直接获取文件流上传
    response = client.put_object(
        Bucket=bucket,
        Body=file.file,
        Key=key,
        StorageClass='STANDARD',
        EnableMD5=False
    )
    logging.info("Image uploaded to COS: %s", image_url)
    return image_url

