# 文件浏览器服务器

一个功能完善的 Web 文件管理工具，支持用户认证、文件操作和代理功能。

## 📖 简介

这是一个基于 Flask 开发的 Web 应用，可以让你通过浏览器安全地管理服务器上的文件和目录。它提供了用户登录认证、文件上传下载、在线编辑、目录管理等核心功能，并支持 HTTP/WebSocket 代理。

## ✨ 主要功能

### 📁 文件管理
- 浏览目录和文件列表
- 上传文件（无类型限制）
- 下载文件
- 在线查看和编辑文本文件
- 创建文件夹
- 重命名文件/文件夹
- 移动文件/文件夹
- 删除文件/文件夹（支持批量删除）

### 👥 用户管理
- 用户注册和登录
- 密码修改
- 管理员可以管理所有用户（创建、禁用、删除、重置密码）
- 登录失败锁定机制（5次失败锁定15分钟）

### 🔐 安全特性
- 会话管理（24小时有效期）
- 密码强度要求（长度、大小写、数字）
- 操作日志记录
- 登录尝试记录
- 路径遍历防护

### 🔀 代理功能
- HTTP/HTTPS 请求代理
- WebSocket 代理（通过 Socket.IO）
- 目标地址白名单控制

### 📊 审计功能（仅管理员）
- 查看文件操作历史
- 查看登录尝试记录
- 系统统计信息

## 🚀 快速开始

### 环境要求

- Python 3.8+
- pip 包管理器

### 安装步骤

1. **下载代码**
```bash
git clone <仓库地址>
cd <项目目录>
```

2. **安装依赖**
```bash
pip install -r requirements.txt
```

### 基础依赖包
```txt
Flask
Flask-CORS
Flask-SQLAlchemy
Flask-Limiter
Flask-SocketIO
Werkzeug
requests
websocket-client
```

### 启动服务器

#### 方式一：直接启动
```bash
python app.py
```

#### 方式二：初始化数据库后启动
```bash
# 先初始化数据库
python app.py --init-db

# 然后正常启动
python app.py
```

#### 方式三：使用自定义配置文件
```bash
python app.py --config /path/to/myconfig.ini
```

## ⚙️ 配置文件

创建 `config.ini` 文件来配置服务器：

```ini
[server]
host = 0.0.0.0
port = 5000

[directory]
root = /path/to/your/files

[ssl]
enabled = false
cert_file = cert.pem
key_file = key.pem

[cors]
allowed_origins = http://localhost:5000,http://127.0.0.1:5000

[security]
max_content_length_mb = 100
session_lifetime_hours = 24

[proxy]
enabled = true
allowed_targets = http://localhost:8000,http://localhost:8080,ws://localhost:8765
```

### 配置说明

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `server.host` | 监听地址 | 0.0.0.0 |
| `server.port` | 监听端口 | 5000 |
| `directory.root` | 文件根目录 | 空（不启用文件功能） |
| `ssl.enabled` | 是否启用HTTPS | false |
| `proxy.enabled` | 是否启用代理 | true |

## 📱 使用说明

### 首次使用

1. **启动服务器**
```bash
python app.py --init-db
python app.py
```

2. **访问页面**
打开浏览器访问：`http://localhost:5000`

3. **登录系统**
- 用户名：`admin`
- 密码：`Admin@123456`

**⚠️ 重要提示**：首次登录后请立即修改管理员密码！

### 文件管理

#### 浏览文件
- 点击文件夹进入子目录
- 面包屑导航可以快速返回上级目录

#### 上传文件
1. 点击"上传"按钮
2. 选择文件（可多选）
3. 等待上传完成

#### 下载文件
- 点击文件旁的"下载"按钮

#### 编辑文件
- 点击文本文件旁的"编辑"按钮
- 在线修改内容后保存（限10MB以内）

#### 新建文件夹
1. 点击"新建文件夹"按钮
2. 输入文件夹名称

#### 重命名
1. 点击项目旁的"重命名"按钮
2. 输入新名称

#### 移动文件/文件夹
1. 选中要移动的项目
2. 点击"移动"按钮
3. 选择目标文件夹

#### 删除
- 单个删除：点击"删除"按钮
- 批量删除：勾选多个项目后点击"批量删除"

### 用户管理（管理员）

#### 创建用户
1. 进入"用户管理"页面
2. 点击"创建用户"
3. 输入用户名和密码

#### 管理用户
- 启用/禁用用户
- 重置用户密码
- 删除用户（不能删除管理员自己）

### 代理功能

#### HTTP 代理
访问：`/proxy/目标地址`
例如：`http://localhost:5000/proxy/api.example.com/data`

#### WebSocket 代理
通过前端 Socket.IO 连接，需要前端配合实现。

## 🔧 API 接口

### 认证相关

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/login` | POST | 用户登录 |
| `/api/logout` | POST | 用户登出 |
| `/api/check-auth` | GET | 检查登录状态 |
| `/api/change-password` | POST | 修改密码 |

### 文件操作

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/filelist` | GET | 获取文件列表 |
| `/upload` | POST | 上传文件 |
| `/download/<path>` | GET | 下载文件 |
| `/read-file/<path>` | GET | 读取文件内容 |
| `/save-file` | POST | 保存文件内容 |
| `/api/rename` | POST | 重命名 |
| `/api/folders` | POST | 创建文件夹 |
| `/api/move` | POST | 移动项目 |
| `/delete` | POST | 删除单个 |
| `/delete-multiple` | POST | 批量删除 |

### 用户管理（管理员）

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/register` | POST | 创建用户 |
| `/api/users` | GET | 获取用户列表 |
| `/api/users/<id>` | DELETE | 删除用户 |
| `/api/users/<id>/toggle-status` | POST | 启用/禁用用户 |
| `/api/admin/users/<id>/password` | POST | 管理员重置密码 |

### 审计日志（管理员）

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/audit/file-operations` | GET | 文件操作日志 |
| `/api/audit/login-attempts` | GET | 登录尝试日志 |
| `/api/stats` | GET | 系统统计信息 |

### 代理相关

| 接口 | 方法 | 说明 |
|------|------|------|
| `/proxy/<path>` | 各种方法 | HTTP/HTTPS代理 |
| `/api/proxy/status` | GET | 代理状态 |
| `/api/proxy/test` | POST | 测试代理目标 |

### 系统

| 接口 | 方法 | 说明 |
|------|------|------|
| `/health` | GET | 健康检查 |

## 🔒 安全说明

### 密码要求
- 最小长度：8个字符
- 必须包含：大写字母、小写字母、数字
- 特殊字符：可选（默认不强制）

### 会话安全
- 会话有效期：24小时
- Cookie：HttpOnly、SameSite=Lax
- 会话存储在服务端

### 访问控制
- 文件操作需要登录
- 用户管理需要管理员权限
- 代理功能需要登录
- `users` 文件夹需要登录才能访问

### 限流保护
- 登录：5次/分钟
- 注册：10次/小时
- 文件操作：按操作类型限制
- 默认全局限流：200次/天，50次/小时

## 📝 日志

日志文件位置：`app.log`
- 自动轮转（10MB/文件，保留10个备份）
- 记录所有操作和错误

## ❓ 常见问题

### Q: 启动时提示数据库错误？
A: 确保 `instance` 目录有写入权限，或运行 `python app.py --init-db` 重新初始化。

### Q: 上传文件失败？
A: 检查 `config.ini` 中的 `max_content_length_mb` 设置是否足够大。

### Q: 无法访问文件？
A: 确保 `directory.root` 配置正确，并且路径存在且可读。

### Q: 忘记管理员密码？
A: 运行 `python app.py --init-db` 重置数据库（会清空所有用户数据）。

### Q: 代理功能无法使用？
A: 检查 `config.ini` 中 `proxy.enabled = true`，并且目标地址在白名单中。

### Q: WebSocket 代理不工作？
A: 确保目标地址以 `ws://` 或 `wss://` 开头，并且在 `allowed_targets` 白名单中。

## 📄 许可证

本项目仅供学习和内部使用。

---

**提示**：生产环境部署时，请务必：
1. 修改默认管理员密码
2. 启用 HTTPS（配置 SSL）
3. 设置合适的文件根目录
4. 根据需要调整白名单