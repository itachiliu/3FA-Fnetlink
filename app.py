"""Flask 应用主文件"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
from datetime import datetime, timedelta
import secrets
import bcrypt
import jwt
import json

from config import Config
from models import db, User, EmailVerification, LoginSession, AuditLog
from totp_manager import generate_totp_secret, verify_totp_code, generate_backup_codes, generate_qr_code
from mailer_manager import generate_verification_code, send_verification_email, send_totp_setup_email


def create_app():
    """创建 Flask 应用"""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # 初始化扩展
    db.init_app(app)
    CORS(app)
    
    # 创建数据库表
    with app.app_context():
        db.create_all()
    
    # 辅助函数
    def get_user_ip():
        """获取用户IP"""
        return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
    
    def get_user_agent():
        """获取用户代理"""
        return request.headers.get('User-Agent', '')
    
    def log_audit(user_id, action, status):
        """记录审计日志"""
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            status=status,
            ip_address=get_user_ip(),
            user_agent=get_user_agent()
        )
        db.session.add(audit_log)
        db.session.commit()
    
    def generate_session_token():
        """生成会话令牌"""
        return secrets.token_hex(32)
    
    def token_required(f):
        """JWT Token 验证装饰器"""
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                auth_header = request.headers['Authorization']
                try:
                    token = auth_header.split(' ')[1]
                except IndexError:
                    return jsonify({'error': 'Token 格式错误'}), 401
            
            if not token:
                return jsonify({'error': 'Token 缺失'}), 401
            
            try:
                data = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
                request.user_id = data['userId']
                request.username = data['username']
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token 已过期'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Token 无效'}), 401
            
            return f(*args, **kwargs)
        
        return decorated
    
    # ===================== API 端点 =====================
    
    # 1. 用户注册
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return jsonify({'error': '用户名、邮箱和密码不能为空'}), 400
        
        if len(password) < 8:
            return jsonify({'error': '密码至少需要8位'}), 400
        
        try:
            # 检查用户是否已存在
            if User.query.filter((User.username == username) | (User.email == email)).first():
                log_audit(None, 'register', 'failed')
                return jsonify({'error': '用户名或邮箱已存在'}), 400
            
            # 加密密码
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # 创建新用户
            user = User(
                username=username,
                email=email,
                password=hashed_password
            )
            db.session.add(user)
            db.session.commit()
            
            log_audit(user.id, 'register', 'success')
            
            return jsonify({
                'message': '注册成功',
                'userId': user.id
            }), 201
        
        except Exception as e:
            db.session.rollback()
            print(f'❌ 注册失败: {e}')
            return jsonify({'error': '服务器错误'}), 500
    
    # 2. 第一步：验证用户名和密码
    @app.route('/api/auth/step1', methods=['POST'])
    def step1():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': '用户名和密码不能为空'}), 400
        
        try:
            user = User.query.filter_by(username=username).first()
            
            if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                log_audit(user.id if user else None, 'login_step1', 'failed')
                return jsonify({'error': '用户名或密码错误'}), 401
            
            # 创建登录会话
            session_token = generate_session_token()
            expires_at = datetime.utcnow() + Config.SESSION_TIMEOUT
            
            session = LoginSession(
                username=username,
                user_id=user.id,
                password_verified=True,
                session_token=session_token,
                expires_at=expires_at
            )
            db.session.add(session)
            db.session.commit()
            
            log_audit(user.id, 'login_step1', 'success')
            
            return jsonify({
                'message': '密码验证成功',
                'sessionToken': session_token,
                'email': user.email
            }), 200
        
        except Exception as e:
            db.session.rollback()
            print(f'❌ 登录第一步失败: {e}')
            return jsonify({'error': '服务器错误'}), 500
    
    # 3. 第二步：发送邮件验证码
    @app.route('/api/auth/step2/send-code', methods=['POST'])
    def send_verification_code():
        data = request.get_json()
        session_token = data.get('sessionToken')
        
        if not session_token:
            return jsonify({'error': '会话令牌无效'}), 400
        
        try:
            session = LoginSession.query.filter_by(session_token=session_token).first()
            
            if not session or session.is_expired():
                return jsonify({'error': '会话已过期'}), 401
            
            user = User.query.filter_by(username=session.username).first()
            
            if not user:
                return jsonify({'error': '用户未找到'}), 500
            
            # 生成验证码
            code = generate_verification_code()
            expires_at = datetime.utcnow() + Config.VERIFICATION_CODE_TIMEOUT
            
            verification = EmailVerification(
                user_id=user.id,
                code=code,
                expires_at=expires_at
            )
            db.session.add(verification)
            db.session.commit()
            
            # 发送邮件
            email_sent = send_verification_email(user.email, code, user.username)
            
            if not email_sent:
                log_audit(user.id, 'email_verification_send', 'failed')
                return jsonify({'error': '邮件发送失败，请重试'}), 500
            
            log_audit(user.id, 'email_verification_send', 'success')
            
            # 隐藏邮箱中间部分
            masked_email = user.email[:2] + '***' + user.email[user.email.find('@')-1:]
            
            return jsonify({
                'message': '验证码已发送',
                'emailTip': masked_email
            }), 200
        
        except Exception as e:
            db.session.rollback()
            print(f'❌ 发送验证码失败: {e}')
            return jsonify({'error': '服务器错误'}), 500
    
    # 4. 第二步：验证邮件验证码
    @app.route('/api/auth/step2/verify-code', methods=['POST'])
    def verify_email_code():
        data = request.get_json()
        session_token = data.get('sessionToken')
        code = data.get('code')
        
        if not session_token or not code:
            return jsonify({'error': '参数缺失'}), 400
        
        try:
            session = LoginSession.query.filter_by(session_token=session_token).first()
            
            if not session or session.is_expired():
                return jsonify({'error': '会话已过期'}), 401
            
            user = User.query.filter_by(username=session.username).first()
            
            if not user:
                return jsonify({'error': '用户未找到'}), 500
            
            # 获取最新的验证码
            verification = EmailVerification.query.filter_by(user_id=user.id).order_by(
                EmailVerification.created_at.desc()
            ).first()
            
            if not verification or not verification.is_valid():
                return jsonify({'error': '验证码已过期或不存在'}), 401
            
            if verification.code != code:
                verification.attempts += 1
                db.session.commit()
                
                if verification.attempts >= 5:
                    return jsonify({'error': '验证次数过多，请重新申请验证码'}), 401
                
                return jsonify({'error': '验证码错误'}), 401
            
            # 更新会话状态
            session.email_verified = True
            db.session.commit()
            
            log_audit(user.id, 'email_verification_verify', 'success')
            
            return jsonify({'message': '邮件验证成功'}), 200
        
        except Exception as e:
            db.session.rollback()
            print(f'❌ 验证邮件失败: {e}')
            return jsonify({'error': '服务器错误'}), 500
    
    # 5. 第三步：获取 TOTP 设置
    @app.route('/api/auth/step3/setup-totp', methods=['POST'])
    def setup_totp():
        data = request.get_json()
        session_token = data.get('sessionToken')
        
        if not session_token:
            return jsonify({'error': '会话令牌无效'}), 400
        
        try:
            session = LoginSession.query.filter_by(session_token=session_token).first()
            
            if not session or session.is_expired() or not session.email_verified:
                return jsonify({'error': '会话已过期或邮件未验证'}), 401
            
            user = User.query.filter_by(username=session.username).first()
            
            if not user:
                return jsonify({'error': '用户未找到'}), 500
            
            # 如果用户已启用TOTP，直接要求验证
            if user.totp_enabled:
                return jsonify({
                    'message': '请输入你的身份验证器中的6位数字',
                    'totpEnabled': True
                }), 200
            
            # 生成新的 TOTP 密钥和二维码
            secret_data = generate_totp_secret(user.username, user.email)
            qr_code = generate_qr_code(secret_data['provisioning_uri'])
            backup_codes = generate_backup_codes()
            
            return jsonify({
                'message': '请扫描二维码设置身份验证器',
                'qrCode': qr_code,
                'secret': secret_data['secret'],
                'backupCodes': backup_codes,
                'totpEnabled': False
            }), 200
        
        except Exception as e:
            print(f'❌ TOTP设置失败: {e}')
            return jsonify({'error': '服务器错误'}), 500
    
    # 6. 第三步：验证 TOTP
    @app.route('/api/auth/step3/verify-totp', methods=['POST'])
    def verify_totp():
        data = request.get_json()
        session_token = data.get('sessionToken')
        totp_code = data.get('totpCode')
        backup_code = data.get('backupCode')
        secret = data.get('secret')  # 用于首次启用TOTP
        
        if not session_token:
            return jsonify({'error': '会话令牌无效'}), 400
        
        if not totp_code and not backup_code:
            return jsonify({'error': '请提供验证码或备用码'}), 400
        
        try:
            session = LoginSession.query.filter_by(session_token=session_token).first()
            
            if not session or session.is_expired() or not session.email_verified:
                return jsonify({'error': '会话已过期'}), 401
            
            user = User.query.filter_by(username=session.username).first()
            
            if not user:
                return jsonify({'error': '用户未找到'}), 500
            
            # 如果用户还未启用TOTP但提供了secret，则首次启用
            if not user.totp_enabled and secret:
                print(f'🔐 首次TOTP设置 - 用户: {user.username}, 验证码: {totp_code}, Secret长度: {len(secret)}')
                if totp_code and verify_totp_code(secret, totp_code):
                    print(f'✅ TOTP验证成功 - 用户: {user.username}')
                    # 验证成功，保存TOTP
                    backup_codes = generate_backup_codes()
                    user.totp_secret = secret
                    user.totp_enabled = True
                    user.backup_codes = json.dumps(backup_codes)
                    db.session.commit()
                    log_audit(user.id, 'totp_setup', 'success')
                else:
                    print(f'❌ TOTP验证失败 - 用户: {user.username}')
                    log_audit(user.id, 'totp_setup', 'failed')
                    return jsonify({'error': '验证码错误，TOTP设置失败'}), 401
            
            # 如果用户已启用TOTP，验证现有的TOTP
            elif user.totp_enabled and user.totp_secret:
                verified = False
                
                # 验证 TOTP 码
                if totp_code:
                    verified = verify_totp_code(user.totp_secret, totp_code)
                
                # 验证备用码
                if not verified and backup_code:
                    backup_codes = json.loads(user.backup_codes or '[]')
                    if backup_code in backup_codes:
                        # 移除使用过的备用码
                        backup_codes.remove(backup_code)
                        user.backup_codes = json.dumps(backup_codes)
                        db.session.commit()
                        verified = True
                
                if not verified:
                    log_audit(user.id, 'totp_verification', 'failed')
                    return jsonify({'error': '验证码或备用码错误'}), 401
            
            else:
                return jsonify({'error': 'TOTP未启用且未提供密钥'}), 401
            
            # 更新会话状态
            session.totp_verified = True
            db.session.commit()
            
            # 生成 JWT Token
            token = jwt.encode({
                'userId': user.id,
                'username': user.username,
                'email': user.email
            }, Config.JWT_SECRET, algorithm='HS256')
            
            log_audit(user.id, 'login_complete', 'success')
            
            return jsonify({
                'message': '登录成功',
                'token': token,
                'user': user.to_dict()
            }), 200
        
        except Exception as e:
            db.session.rollback()
            print(f'❌ TOTP验证失败: {e}')
            return jsonify({'error': '服务器错误'}), 500
    
    # 7. 启用 TOTP
    @app.route('/api/auth/enable-totp', methods=['POST'])
    @token_required
    def enable_totp():
        data = request.get_json()
        totp_code = data.get('totpCode')
        secret = data.get('secret')
        
        if not totp_code or not secret:
            return jsonify({'error': '参数缺失'}), 400
        
        try:
            user = User.query.get(request.user_id)
            
            if not user:
                return jsonify({'error': '用户未找到'}), 404
            
            # 验证 TOTP 码
            if not verify_totp_code(secret, totp_code):
                return jsonify({'error': '验证码错误'}), 401
            
            backup_codes = generate_backup_codes()
            
            user.totp_secret = secret
            user.totp_enabled = True
            user.backup_codes = json.dumps(backup_codes)
            db.session.commit()
            
            log_audit(user.id, 'totp_enabled', 'success')
            
            return jsonify({
                'message': 'TOTP已启用',
                'backupCodes': backup_codes
            }), 200
        
        except Exception as e:
            db.session.rollback()
            print(f'❌ 启用TOTP失败: {e}')
            return jsonify({'error': '服务器错误'}), 500
    
    # 8. 验证 Token
    @app.route('/api/auth/verify', methods=['GET'])
    @token_required
    def verify_token():
        try:
            user = User.query.get(request.user_id)
            return jsonify({
                'valid': True,
                'user': user.to_dict()
            }), 200
        except Exception as e:
            print(f'❌ Token验证失败: {e}')
            return jsonify({'error': '服务器错误'}), 500
    
    # 健康检查
    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    
    # 提供静态前端
    @app.route('/')
    def index():
        from flask import send_file
        return send_file('public/index.html')
    
    return app


if __name__ == '__main__':
    app = create_app()
    
    print("""
╔══════════════════════════════════════════════╗
║     三因素认证系统 - 服务器已启动（Python）    ║
║     Server: http://localhost:5000            ║
║     前端: http://localhost:5000/             ║
╚══════════════════════════════════════════════╝
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
