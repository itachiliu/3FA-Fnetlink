@echo off
REM Docker 三因素认证系统启动脚本（Windows）

echo ===================================
echo 三因素认证系统 (Docker 版本)
echo ===================================
echo.

REM 检查 Docker 是否安装
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo 错误：未检测到 Docker
    echo 请先安装 Docker Desktop：https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

echo ✓ Docker 已检测

REM 检查 docker-compose 是否可用
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo 错误：未检测到 docker-compose
    echo 请确保 Docker Desktop 中已安装 docker-compose
    pause
    exit /b 1
)

echo ✓ docker-compose 已检测
echo.

REM 显示菜单
echo 请选择操作：
echo 1. 启动应用 (docker-compose up)
echo 2. 后台运行 (docker-compose up -d)
echo 3. 停止应用 (docker-compose down)
echo 4. 查看日志 (docker-compose logs -f)
echo 5. 重新构建 (docker-compose up -d --build)
echo 6. 清理所有容器和数据 (docker-compose down -v)
echo.

set /p choice="请输入选择 (1-6): "

if "%choice%"=="1" (
    echo.
    echo 正在启动应用...
    docker-compose up
) else if "%choice%"=="2" (
    echo.
    echo 正在后台启动应用...
    docker-compose up -d
    echo ✓ 应用已启动
    echo.
    echo 前端地址: http://localhost:5000
    echo API 地址: http://localhost:5000/api
    echo MailHog: http://localhost:8025
) else if "%choice%"=="3" (
    echo.
    echo 正在停止应用...
    docker-compose down
    echo ✓ 应用已停止
) else if "%choice%"=="4" (
    echo.
    echo 显示日志 (按 Ctrl+C 退出)...
    docker-compose logs -f
) else if "%choice%"=="5" (
    echo.
    echo 正在重新构建...
    docker-compose up -d --build
    echo ✓ 重新构建完成
    echo.
    echo 前端地址: http://localhost:5000
    echo API 地址: http://localhost:5000/api
) else if "%choice%"=="6" (
    echo.
    echo 确认要删除所有容器和数据吗？ (Y/N)
    set /p confirm="确认: "
    if /i "%confirm%"=="Y" (
        docker-compose down -v
        echo ✓ 已清理所有数据
    ) else (
        echo 已取消
    )
) else (
    echo 无效选择
)

pause
