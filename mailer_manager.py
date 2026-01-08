"""邮件相关功能"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
from config import Config


def generate_verification_code():
    """生成随机验证码"""
    return str(random.randint(100000, 999999))


def send_verification_email(email, code, username):
    """发送邮件验证码"""
    try:
        # 构建邮件内容
        subject = f'{Config.APP_NAME} - 邮件验证码'
        
        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #003366;">邮件验证码</h2>
            <p>尊敬的 {username},</p>
            <p>您正在登录 {Config.APP_NAME}。请使用以下验证码完成身份验证：</p>
            <div style="background: #f0f0f0; padding: 20px; border-radius: 6px; text-align: center; margin: 20px 0;">
                <h1 style="color: #ff6b35; letter-spacing: 2px; margin: 0;">{code}</h1>
            </div>
            <p style="color: #999; font-size: 12px;">验证码有效期为 10 分钟。请勿将此代码分享给任何人。</p>
            <p style="color: #999; font-size: 12px;">如果这不是您的操作，请忽略此邮件。</p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="color: #999; font-size: 11px;">© 2026 {Config.APP_NAME}. All rights reserved.</p>
        </div>
        """
        
        # 创建邮件
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = Config.EMAIL_USER
        msg['To'] = email
        
        # 添加纯文本和HTML版本
        text_part = MIMEText(f'您的验证码是: {code}', 'plain', 'utf-8')
        html_part = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(text_part)
        msg.attach(html_part)
        
        # 发送邮件
        server = smtplib.SMTP(Config.EMAIL_HOST, Config.EMAIL_PORT)
        server.starttls()
        server.login(Config.EMAIL_USER, Config.EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f'✅ 验证码已发送至 {email}')
        return True
    except Exception as error:
        print(f'❌ 发送邮件失败: {error}')
        return False


def send_totp_setup_email(email, qr_code_url, secret, username):
    """发送 TOTP 设置邮件"""
    try:
        subject = f'{Config.APP_NAME} - 启用双因素认证'
        
        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #003366;">双因素认证设置</h2>
            <p>尊敬的 {username},</p>
            <p>您已启用双因素认证。请使用您的身份验证器应用扫描以下二维码或输入密钥：</p>
            <div style="text-align: center; margin: 20px 0;">
                <img src="{qr_code_url}" style="width: 250px; height: 250px; border: 1px solid #ddd; padding: 10px; border-radius: 6px;">
            </div>
            <p style="background: #f0f0f0; padding: 15px; border-radius: 6px; word-break: break-all;">
                <strong>密钥：</strong> {secret}
            </p>
            <p style="color: #999; font-size: 12px;">推荐应用：Google Authenticator, Microsoft Authenticator, Authy</p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="color: #999; font-size: 11px;">© 2026 {Config.APP_NAME}. All rights reserved.</p>
        </div>
        """
        
        # 创建邮件
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = Config.EMAIL_USER
        msg['To'] = email
        
        # 添加纯文本和HTML版本
        text_part = MIMEText(f'您的TOTP密钥是: {secret}', 'plain', 'utf-8')
        html_part = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(text_part)
        msg.attach(html_part)
        
        # 发送邮件
        server = smtplib.SMTP(Config.EMAIL_HOST, Config.EMAIL_PORT)
        server.starttls()
        server.login(Config.EMAIL_USER, Config.EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as error:
        print(f'❌ 发送邮件失败: {error}')
        return False
