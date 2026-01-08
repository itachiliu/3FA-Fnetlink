#!/bin/bash

# Docker 三因素认证系统启动脚本（Linux/Mac）

echo "==================================="
echo "三因素认证系统 (Docker 版本)"
echo "==================================="
echo ""

# 检查 Docker 是否安装
if ! command -v docker &> /dev/null; then
    echo "错误：未检测到 Docker"
    echo "请先安装 Docker：https://docs.docker.com/get-docker/"
    exit 1
fi

echo "✓ Docker 已检测"

# 检查 docker-compose 是否可用
if ! command -v docker-compose &> /dev/null; then
    echo "错误：未检测到 docker-compose"
    echo "请确保已安装 docker-compose"
    exit 1
fi

echo "✓ docker-compose 已检测"
echo ""

# 显示菜单
echo "请选择操作："
echo "1. 启动应用 (docker-compose up)"
echo "2. 后台运行 (docker-compose up -d)"
echo "3. 停止应用 (docker-compose down)"
echo "4. 查看日志 (docker-compose logs -f)"
echo "5. 重新构建 (docker-compose up -d --build)"
echo "6. 清理所有容器和数据 (docker-compose down -v)"
echo ""

read -p "请输入选择 (1-6): " choice

case $choice in
    1)
        echo ""
        echo "正在启动应用..."
        docker-compose up
        ;;
    2)
        echo ""
        echo "正在后台启动应用..."
        docker-compose up -d
        echo "✓ 应用已启动"
        echo ""
        echo "前端地址: http://localhost:5000"
        echo "API 地址: http://localhost:5000/api"
        echo "MailHog: http://localhost:8025"
        ;;
    3)
        echo ""
        echo "正在停止应用..."
        docker-compose down
        echo "✓ 应用已停止"
        ;;
    4)
        echo ""
        echo "显示日志 (按 Ctrl+C 退出)..."
        docker-compose logs -f
        ;;
    5)
        echo ""
        echo "正在重新构建..."
        docker-compose up -d --build
        echo "✓ 重新构建完成"
        echo ""
        echo "前端地址: http://localhost:5000"
        echo "API 地址: http://localhost:5000/api"
        ;;
    6)
        echo ""
        read -p "确认要删除所有容器和数据吗？ (Y/N): " confirm
        if [[ $confirm == [Yy] ]]; then
            docker-compose down -v
            echo "✓ 已清理所有数据"
        else
            echo "已取消"
        fi
        ;;
    *)
        echo "无效选择"
        ;;
esac
