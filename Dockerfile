# Python 3.11 官方镜像
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements-python.txt .

# 创建虚拟环境并安装依赖
RUN python -m venv /opt/venv

# 激活虚拟环境（通过设置PATH）
ENV PATH="/opt/venv/bin:$PATH"

# 升级 pip 和 setuptools
RUN pip install --upgrade pip setuptools wheel

# 安装 Python 依赖
RUN pip install -r requirements-python.txt

# 复制应用代码
COPY . .

# 创建非 root 用户（安全最佳实践）
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# 暴露端口
EXPOSE 5000

# 启动命令
CMD ["python", "app.py"]
