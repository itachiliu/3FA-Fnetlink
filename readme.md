# 光联世纪三因素认证系统

> 由光联世纪与澳门科技大学在澳门科技发展基金（FDCT）的支持下完成的企业级三因素认证解决方案

## 📋 项目背景

本项目是光联世纪与澳门科技大学合作开发的高安全性认证系统，在**澳门科技发展基金（FDCT）**的支持下完成。该系统提供企业级的三因素认证能力，确保用户账户的最高安全保护。

---

## ✨ 核心功能

### 🔐 三因素认证流程

系统采用三层递进式认证机制：

1. **第一因素 - 密码认证**
   - 用户名 + 密码验证
   - Bcrypt 加密存储（10 轮）
   - 强密码验证

2. **第二因素 - 邮件验证**
   - 发送 6 位数字验证码到注册邮箱
   - 60 秒倒计时重新发送
   - 验证码 5 分钟内有效

3. **第三因素 - TOTP 双因素认证**
   - 基于时间的一次性密码（RFC 6238）
   - 支持 Google Authenticator、Microsoft Authenticator 等应用
   - 自动生成 10 个备用码（应急使用）

### 🛡️ 安全特性

✅ 密码 Bcrypt 加密（10 轮）  
✅ JWT 令牌认证（HS256，24 小时过期）  
✅ 邮件验证码验证  
✅ TOTP 双因素认证  
✅ 备用码系统  
✅ 会话管理与超时控制  
✅ 审计日志记录（所有认证事件）  
✅ 用户信息隔离与授权  

---

## 🚀 快速开始

### 方式 1：Docker（推荐）

```bash
# 克隆或进入项目
cd auth-system

# 配置邮箱（编辑 .env 文件）
# EMAIL_USER=your-email@qq.com
# EMAIL_PASSWORD=your-app-password

# 启动服务
docker-compose up -d

# 访问应用
# 前端：http://localhost:5000
# API：http://localhost:5000/api
```

### 方式 2：本地运行

```bash
# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 安装依赖
pip install -r requirements-python.txt

# 配置环境变量
# 编辑 .env 文件

# 运行应用
python app.py
```

---

## 📖 使用说明

### 1. 注册账户

访问 http://localhost:5000，点击"注册账户"：
- 输入用户名
- 输入邮箱地址
- 设置密码
- 点击注册

### 2. 第一次登录

**第一步**：输入用户名和密码
- 系统验证账户信息

**第二步**：邮件验证
- 检查注册邮箱，查收验证码
- 输入 6 位验证码
- 如未收到可点击"重新发送"（60秒后可用）

**第三步**：TOTP 设置
- 使用 Google Authenticator 等应用扫描二维码
- 输入应用中显示的 6 位验证码
- **重要**：保存好系统生成的 10 个备用码

完成登录后，系统返回 JWT token

### 3. 后续登录

使用相同的三步流程即可，已保存的 TOTP 密钥会自动使用。

---

## 🔧 配置说明

### .env 文件配置

```env
# Flask 应用
FLASK_ENV=development
PORT=5000

# JWT 密钥（必须修改！）
JWT_SECRET=your-super-secret-key-change-this
SECRET_KEY=your-secret-key-change-this

# 邮件配置（以 QQ 邮箱为例）
EMAIL_USER=1234567890@qq.com
EMAIL_PASSWORD=your-app-password      # 使用邮箱授权码，非登录密码
EMAIL_HOST=smtp.qq.com
EMAIL_PORT=587
EMAIL_FROM_NAME=光联世纪验证系统

# 应用配置
APP_NAME=光联世纪
BASE_URL=http://localhost:5000
```

### 获取 QQ 邮箱授权码

1. 登录 [QQ 邮箱](https://mail.qq.com)
2. 进入 **设置** → **账户**
3. 找到 **POP3/SMTP 服务** → 点击 **开启**
4. 系统会生成一个 16 位授权码
5. 复制该授权码到 `.env` 中的 `EMAIL_PASSWORD`

---

## 📊 技术架构

### 后端技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| Flask | 3.0 | Web 框架 |
| SQLAlchemy | 3.1 | 数据库 ORM |
| PyJWT | 2.8.0 | JWT 认证 |
| pyotp | 2.9.0 | TOTP 实现 |
| bcrypt | 4.1.1 | 密码加密 |
| qrcode | 7.4.2 | 二维码生成 |

### 前端技术栈

- HTML5 + CSS3 + JavaScript（无框架依赖）
- 响应式设计
- AJAX 异步请求

### 数据库

- SQLite（开发/测试）
- 可扩展支持 PostgreSQL、MySQL

---

## 📂 项目结构

```
auth-system/
├── app.py                      # Flask 主应用
├── models.py                   # 数据库模型
├── config.py                   # 配置管理
├── totp_manager.py            # TOTP 管理
├── mailer_manager.py          # 邮件服务
├── Dockerfile                  # 容器镜像
├── docker-compose.yml         # 开发环境编排
├── docker-compose.prod.yml    # 生产环境编排
├── public/index.html          # 前端页面
├── .env                        # 环境配置
└── requirements-python.txt    # Python 依赖
```

---

## 🔒 安全建议

### 开发环境

✓ 使用 `.env` 管理敏感信息  
✓ 启用 Flask DEBUG 模式便于调试  
✓ 使用 SQLite 快速测试  

### 生产环境

⚠️ **必须执行以下操作：**

1. **修改密钥**
   ```env
   JWT_SECRET=生成一个强密钥（至少32字符）
   SECRET_KEY=生成另一个强密钥
   ```

2. **启用 HTTPS**
   - 配置 SSL 证书
   - 在反向代理中启用

3. **数据库**
   - 迁移到 PostgreSQL 或 MySQL
   - 启用数据库备份
   - 定期安全更新

4. **应用部署**
   - 使用 Gunicorn 或 uWSGI
   - 配置 Nginx 反向代理
   - 启用速率限制防止暴力破解
   - 配置 CORS 白名单

5. **监控与日志**
   - 监控审计日志
   - 设置告警机制
   - 定期安全审计

---

## 💻 API 文档

### 用户注册
```
POST /api/auth/register
Content-Type: application/json

{
  "username": "user123",
  "email": "user@example.com",
  "password": "SecurePass123"
}

返回: { "id": 1, "username": "user123", "email": "user@example.com" }
```

### 第一步验证（密码）
```
POST /api/auth/step1
{ "username": "user123", "password": "SecurePass123" }

返回: { "sessionToken": "...", "email": "user@example.com" }
```

### 第二步验证（邮件验证码）
```
POST /api/auth/step2/verify-code
{ "sessionToken": "...", "code": "123456" }
```

### 第三步验证（TOTP）
```
POST /api/auth/step3/verify-totp
{ "sessionToken": "...", "totpCode": "123456" }

返回: { "token": "JWT-TOKEN", "user": {...} }
```

### 健康检查
```
GET /api/health

返回: { "status": "ok", "timestamp": "..." }
```

---

## 🐛 故障排除

### 问题 1：Docker 启动失败
```bash
# 查看详细日志
docker-compose logs -f

# 重新构建
docker-compose build --no-cache
docker-compose up
```

### 问题 2：邮件无法发送
- 检查 `.env` 中的邮箱配置
- 确认邮箱已启用 SMTP 服务
- 验证授权码是否正确

### 问题 3：TOTP 验证失败
- 确认客户端和服务器时间同步
- 检查验证器应用中的密钥是否正确
- 尝试使用备用码

### 问题 4：前端无法访问 API
- 检查 API 地址是否正确（`http://localhost:5000/api`）
- 查看浏览器控制台是否有 CORS 错误
- 确认后端服务正在运行

---

## 📱 支持的验证器应用

- ✅ Google Authenticator
- ✅ Microsoft Authenticator
- ✅ Authy
- ✅ FreeOTP
- ✅ 1Password
- ✅ Lastpass Authenticator

---

## 📄 许可证

MIT License

---

## 🙏 致谢

感谢**澳门科技发展基金（FDCT）**的资助支持，使本项目得以顺利完成。

本项目由以下机构合作开发：
- 🏢 光联世纪
- 🎓 澳门科技大学

---

**更新时间**：2025年10月  
**版本**：1.0.0  


