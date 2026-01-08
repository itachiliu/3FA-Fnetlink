"""应用配置"""
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

# 应用配置
class Config:
    """基础配置"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///auth.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT配置
    JWT_SECRET = os.getenv('JWT_SECRET', 'jwt-secret-key-change-in-production')
    JWT_EXPIRY = '24h'
    
    # 邮件配置
    EMAIL_USER = os.getenv('EMAIL_USER')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
    EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.qq.com')
    EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
    APP_NAME = os.getenv('APP_NAME', '光联世纪')
    
    # 会话配置
    SESSION_TIMEOUT = timedelta(minutes=15)
    VERIFICATION_CODE_TIMEOUT = timedelta(minutes=10)
