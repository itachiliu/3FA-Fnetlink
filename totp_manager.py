"""TOTP 相关功能"""
import pyotp
import qrcode
from io import BytesIO
import base64


def generate_totp_secret(username, email):
    """生成 TOTP 密钥"""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    # 生成 provisioning URI 用于二维码
    provisioning_uri = totp.provisioning_uri(
        name=email,
        issuer_name='光联世纪'
    )
    return {
        'secret': secret,
        'provisioning_uri': provisioning_uri
    }


def verify_totp_code(secret, token):
    """验证 TOTP 码"""
    try:
        totp = pyotp.TOTP(secret)
        # 确保 token 是字符串
        token_str = str(token).strip()
        # 允许前后2个时间窗口（60秒）
        result = totp.verify(token_str, valid_window=2)
        print(f'🔍 TOTP验证: secret={secret[:8]}..., token={token_str}, result={result}')
        return result
    except Exception as e:
        print(f'❌ TOTP验证异常: {e}')
        return False


def generate_backup_codes(count=10):
    """生成备用码"""
    import random
    import string
    codes = []
    for _ in range(count):
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        codes.append(code)
    return codes


def generate_qr_code(provisioning_uri):
    """生成 QR 码"""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # 生成图像
        img = qr.make_image(fill_color="black", back_color="white")
        
        # 转换为 Base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        # 只返回 Base64 字符串，不包含前缀
        return img_base64
    except Exception as e:
        print(f'❌ 生成二维码失败: {e}')
        raise
