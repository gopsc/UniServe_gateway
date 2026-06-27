from flask import Flask, render_template, send_from_directory, jsonify, request, Response, session, send_file, stream_with_context, redirect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import mimetypes
import argparse
import secrets
import json
import datetime
import requests
from base64 import b64encode, b64decode
import shutil
import configparser
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys
import uuid
import threading
import websocket

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 添加文件日志
file_handler = RotatingFileHandler('app.log', maxBytes=10485760, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)

# 添加命令行参数解析
parser = argparse.ArgumentParser(description='Flask Directory Browser with User Authentication')
parser.add_argument('--init-db', action='store_true', help='Initialize database and create default user (then exit)')
parser.add_argument('--config', type=str, default='config.ini', help='Configuration file path (default: config.ini)')
args = parser.parse_args()

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ==================== 时间辅助函数 ====================
def local_now():
    """返回当前本地时间"""
    return datetime.datetime.now()

def local_utcnow():
    """返回当前UTC时间（用于API兼容）"""
    return datetime.datetime.utcnow()

# ==================== 配置类 ====================
class Config:
    """应用配置类"""
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    
    basedir = os.path.abspath(os.path.dirname(__file__))
    instance_path = os.path.join(basedir, 'instance')
    os.makedirs(instance_path, exist_ok=True)
    
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(instance_path, 'users.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = datetime.timedelta(hours=24)
    
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024
    UPLOAD_EXTENSIONS = None
    
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGITS = True
    PASSWORD_REQUIRE_SPECIAL = False

app.config.from_object(Config)
logger.info(f"Database path: {app.config['SQLALCHEMY_DATABASE_URI']}")

# ==================== 初始化扩展 ====================
db = SQLAlchemy(app)

CORS(app, 
     supports_credentials=True,
     origins=['http://localhost:5000', 'http://127.0.0.1:5000', 'http://localhost:3000'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     allow_headers=['Content-Type', 'Authorization'])

# ==================== 配置文件加载 ====================
CONFIG_FILE = args.config

file_config = {
    'server': {
        'host': '0.0.0.0',
        'port': '5000'
    },
    'directory': {
        'root': ''
    },
    'ssl': {
        'enabled': 'false',
        'cert_file': 'cert.pem',
        'key_file': 'key.pem'
    },
    'cors': {
        'allowed_origins': 'http://localhost:5000,http://127.0.0.1:5000,http://localhost:3000'
    },
    'security': {
        'max_content_length_mb': '100',
        'session_lifetime_hours': '24',
        'rate_limit_default': '2000 per day;500 per hour;50 per minute;10 per second',  # 默认为空，表示无限流
        'rate_limit_enabled': 'false'  # 新增：是否启用限流
    },
    'proxy': {
        'enabled': 'true',
        'allowed_targets': 'http://localhost:5001,ws://localhost:5002,http://localhost:5200,http://localhost:8000,ws://localhost:8765' 
    }
}

if os.path.exists(CONFIG_FILE):
    config_parser = configparser.ConfigParser()
    config_parser.read(CONFIG_FILE, encoding='utf-8')
    
    if 'server' in config_parser:
        for key, value in config_parser['server'].items():
            if key in file_config['server']:
                file_config['server'][key] = value
    if 'directory' in config_parser:
        for key, value in config_parser['directory'].items():
            if key in file_config['directory']:
                file_config['directory'][key] = value
    if 'ssl' in config_parser:
        for key, value in config_parser['ssl'].items():
            if key in file_config['ssl']:
                file_config['ssl'][key] = value
    if 'cors' in config_parser:
        for key, value in config_parser['cors'].items():
            if key in file_config['cors']:
                file_config['cors'][key] = value
    if 'security' in config_parser:
        for key, value in config_parser['security'].items():
            if key in file_config['security']:
                file_config['security'][key] = value
    if 'proxy' in config_parser:
        for key, value in config_parser['proxy'].items():
            if key in file_config['proxy']:
                file_config['proxy'][key] = value

if 'security' in file_config:
    if file_config['security'].get('max_content_length_mb'):
        app.config['MAX_CONTENT_LENGTH'] = int(file_config['security']['max_content_length_mb']) * 1024 * 1024
    if file_config['security'].get('session_lifetime_hours'):
        app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=int(file_config['security']['session_lifetime_hours']))

if 'cors' in file_config and file_config['cors'].get('allowed_origins'):
    allowed_origins = [origin.strip() for origin in file_config['cors']['allowed_origins'].split(',')]
    CORS(app, 
         supports_credentials=True,
         origins=allowed_origins,
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         allow_headers=['Content-Type', 'Authorization'])

HTML_ROOT_DIR = file_config['directory']['root']
FILESYSTEM_ENABLED = bool(HTML_ROOT_DIR and HTML_ROOT_DIR.strip())

if FILESYSTEM_ENABLED:
    try:
        Path(HTML_ROOT_DIR).mkdir(parents=True, exist_ok=True)
        logger.info(f"Created or verified directory: {HTML_ROOT_DIR}")
    except Exception as e:
        logger.error(f"Failed to create directory {HTML_ROOT_DIR}: {str(e)}")
        FILESYSTEM_ENABLED = False

SSL_ENABLED = file_config['ssl'].get('enabled', 'false').lower() == 'true'
SSL_CERT_FILE = file_config['ssl'].get('cert_file', 'cert.pem')
SSL_KEY_FILE = file_config['ssl'].get('key_file', 'key.pem')

PROXY_ENABLED = file_config['proxy'].get('enabled', 'true').lower() == 'true'
PROXY_ALLOWED_TARGETS = []
if file_config['proxy'].get('allowed_targets'):
    PROXY_ALLOWED_TARGETS = [target.strip() for target in file_config['proxy']['allowed_targets'].split(',') if target.strip()]
logger.info(f"Proxy enabled: {PROXY_ENABLED}, allowed targets: {PROXY_ALLOWED_TARGETS}")

# ==================== 初始化 Limiter（从配置文件读取） ====================
rate_limit_enabled = file_config['security'].get('rate_limit_enabled', 'false').lower() == 'true'
rate_limit_config = file_config['security'].get('rate_limit_default', '')

if rate_limit_enabled and rate_limit_config and rate_limit_config.strip():
    # 解析配置，支持分号分隔的多个限制
    limits = [limit.strip() for limit in rate_limit_config.split(';') if limit.strip()]
    logger.info(f"限流已启用，限制规则: {limits}")
else:
    limits = []  # 无限制
    logger.info("限流已禁用")

try:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=limits,
        storage_uri="memory://"
    )
    logger.info(f"使用 Flask-Limiter 3.0+ 初始化方式，限流配置: {limits if limits else '无限制'}")
except TypeError:
    try:
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=limits,
            storage_uri="memory://"
        )
        logger.info(f"使用 Flask-Limiter 2.x 初始化方式，限流配置: {limits if limits else '无限制'}")
    except TypeError as e:
        logger.warning(f"Limiter初始化失败: {e}，使用基础配置")
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=limits
        )

# ==================== 视频文件支持的MIME类型 ====================
VIDEO_MIME_TYPES = {
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.ogg': 'video/ogg',
    '.ogv': 'video/ogg',
    '.avi': 'video/x-msvideo',
    '.mov': 'video/quicktime',
    '.flv': 'video/x-flv',
    '.mkv': 'video/x-matroska',
    '.wmv': 'video/x-ms-wmv',
    '.m4v': 'video/x-m4v',
    '.3gp': 'video/3gpp',
    '.3g2': 'video/3gpp2',
    '.ts': 'video/mp2t',
    '.m3u8': 'application/x-mpegURL',
    '.mpd': 'application/dash+xml',
}

AUDIO_MIME_TYPES = {
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.ogg': 'audio/ogg',
    '.oga': 'audio/ogg',
    '.flac': 'audio/flac',
    '.aac': 'audio/aac',
    '.m4a': 'audio/mp4',
    '.wma': 'audio/x-ms-wma',
}

def is_video_file(filename):
    """检查文件是否为视频文件"""
    ext = os.path.splitext(filename)[1].lower()
    return ext in VIDEO_MIME_TYPES

def is_audio_file(filename):
    """检查文件是否为音频文件"""
    ext = os.path.splitext(filename)[1].lower()
    return ext in AUDIO_MIME_TYPES

def is_media_file(filename):
    """检查文件是否为媒体文件（视频或音频）"""
    return is_video_file(filename) or is_audio_file(filename)

def get_media_mime_type(filename):
    """获取媒体文件的MIME类型"""
    ext = os.path.splitext(filename)[1].lower()
    if ext in VIDEO_MIME_TYPES:
        return VIDEO_MIME_TYPES[ext]
    if ext in AUDIO_MIME_TYPES:
        return AUDIO_MIME_TYPES[ext]
    return 'application/octet-stream'

# ==================== 权限检查辅助函数 ====================
def check_file_access(file_path, operation='read'):
    """
    检查用户是否有权限访问指定文件/目录
    返回 (has_access, error_message)
    """
    if 'user_id' not in session:
        return False, "请先登录"
    
    user_id = session['user_id']
    username = session['username']
    
    # Admin 用户（user_id == 1）有完全访问权限
    if user_id == 1:
        return True, None
    
    # 普通用户：只能访问 users/用户名/ 目录下的内容
    # 获取相对于根目录的路径
    try:
        rel_path = os.path.relpath(file_path, HTML_ROOT_DIR)
    except ValueError:
        return False, "无效的路径"
    
    # 如果路径是 '.'，表示根目录，普通用户不能访问根目录
    if rel_path == '.':
        return False, "普通用户只能访问自己的文件夹"
    
    # 标准化路径（使用正斜杠）
    rel_path = rel_path.replace('\\', '/')
    path_parts = rel_path.split('/')
    
    # 检查第一级目录是否是 'users'
    if len(path_parts) < 1 or path_parts[0] != 'users':
        return False, f"普通用户只能访问 users 目录下的内容"
    
    # 检查第二级目录是否是用户自己的用户名
    if len(path_parts) < 2 or path_parts[1] != username:
        return False, f"普通用户只能访问自己用户名对应的文件夹 (users/{username}/)"
    
    return True, None

def get_user_accessible_path(requested_path):
    """
    获取用户可访问的路径
    未登录: 返回请求路径（但限制不能访问 users 目录）
    Admin: 返回原始路径
    普通用户: 确保路径在 users/用户名/ 下
    """
    # 未登录用户：可以访问根目录，但不能访问 users 目录
    if 'user_id' not in session:
        if requested_path and requested_path.strip():
            # 标准化路径
            check_path = requested_path.strip().lstrip('/').replace('\\', '/')
            # 检查是否尝试访问 users 目录
            if check_path == 'users' or check_path.startswith('users/'):
                return None, "未登录用户不能访问 users 目录"
        return requested_path, None
    
    user_id = session['user_id']
    username = session['username']
    
    # Admin 用户可以访问任何路径
    if user_id == 1:
        return requested_path, None
    
    # 普通用户：确保路径在 users/用户名/ 下
    # 如果请求的是 users 目录但不是自己的，重定向
    if requested_path is None or requested_path == '':
        # 访问根目录，重定向到用户自己的目录
        return f"users/{username}", None
    
    # 标准化请求路径
    requested_path = requested_path.lstrip('/')
    path_parts = requested_path.split('/')
    
    # 如果请求路径不以 users/用户名 开头，重定向
    if len(path_parts) < 2 or path_parts[0] != 'users' or path_parts[1] != username:
        return f"users/{username}", None
    
    return requested_path, None

# ==================== WebSocket 代理管理 ====================
class WebSocketProxyManager:
    def __init__(self):
        self.active_connections = {}
        self.lock = threading.Lock()
    
    def add_connection(self, sid, target_url):
        with self.lock:
            self.active_connections[sid] = {
                'target_url': target_url,
                'target_ws': None,
                'thread': None
            }
        return sid
    
    def remove_connection(self, sid):
        with self.lock:
            if sid in self.active_connections:
                conn = self.active_connections[sid]
                if conn['target_ws']:
                    try:
                        conn['target_ws'].close()
                    except:
                        pass
                del self.active_connections[sid]
    
    def get_connection(self, sid):
        with self.lock:
            return self.active_connections.get(sid)

ws_manager = WebSocketProxyManager()

def websocket_proxy_thread(sid, target_url):
    """WebSocket 代理线程"""
    target_ws = None
    try:
        target_ws = websocket.WebSocket()
        target_ws.connect(target_url)
        
        with ws_manager.lock:
            if sid in ws_manager.active_connections:
                ws_manager.active_connections[sid]['target_ws'] = target_ws
        
        running = True
        
        def forward_target_to_client():
            nonlocal running
            try:
                while running:
                    try:
                        message = target_ws.recv()
                        if message is None:
                            break
                        socketio.emit('ws_message', {
                            'type': 'message',
                            'data': message
                        }, room=sid)
                    except Exception as e:
                        logger.error(f"Target to client error: {e}")
                        break
            except Exception as e:
                logger.error(f"Target to client thread error: {e}")
            finally:
                running = False
                ws_manager.remove_connection(sid)
        
        thread = threading.Thread(target=forward_target_to_client)
        thread.daemon = True
        thread.start()
        
        thread.join()
        
    except Exception as e:
        logger.error(f"WebSocket proxy error: {e}")
        socketio.emit('ws_error', {'error': str(e)}, room=sid)
    finally:
        if target_ws:
            try:
                target_ws.close()
            except:
                pass
        ws_manager.remove_connection(sid)

# ==================== Socket.IO 事件处理 ====================
@socketio.on('connect')
def handle_connect():
    """客户端连接"""
    logger.info(f"Client connected: {request.sid}")
    if 'user_id' not in session:
        logger.warning(f"Unauthorized WebSocket connection from {request.sid}")
        return False
    emit('connected', {'message': 'WebSocket connected successfully'})

@socketio.on('disconnect')
def handle_disconnect():
    """客户端断开连接"""
    logger.info(f"Client disconnected: {request.sid}")
    ws_manager.remove_connection(request.sid)

@socketio.on('ws_connect')
def handle_ws_connect(data):
    """处理 WebSocket 代理连接请求"""
    try:
        target_url = data.get('target_url')
        if not target_url:
            emit('ws_error', {'error': 'No target URL provided'})
            return
        
        is_allowed = False
        for allowed_target in PROXY_ALLOWED_TARGETS:
            if target_url.startswith(allowed_target):
                is_allowed = True
                break
        
        if not is_allowed:
            emit('ws_error', {'error': f'Target not allowed: {target_url}'})
            return
        
        logger.info(f"User {session.get('username')} connecting to {target_url}")
        
        ws_manager.add_connection(request.sid, target_url)
        
        thread = threading.Thread(
            target=websocket_proxy_thread,
            args=(request.sid, target_url)
        )
        thread.daemon = True
        thread.start()
        
        emit('ws_connected', {'message': f'Connected to {target_url}'})
        
    except Exception as e:
        logger.error(f"WebSocket connect error: {e}")
        emit('ws_error', {'error': str(e)})

@socketio.on('ws_send')
def handle_ws_send(data):
    """发送消息到目标 WebSocket"""
    try:
        message = data.get('message')
        if not message:
            emit('ws_error', {'error': 'No message provided'})
            return
        
        conn = ws_manager.get_connection(request.sid)
        if not conn or not conn['target_ws']:
            emit('ws_error', {'error': 'Not connected to target'})
            return
        
        conn['target_ws'].send(message)
        
    except Exception as e:
        logger.error(f"WebSocket send error: {e}")
        emit('ws_error', {'error': str(e)})

# ==================== 自定义异常 ====================
class APIError(Exception):
    def __init__(self, message, status_code=400, error_code=None):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(self.message)

@app.errorhandler(APIError)
def handle_api_error(error):
    response = {'error': error.message}
    if error.error_code:
        response['code'] = error.error_code
    return jsonify(response), error.status_code

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': '资源不存在'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': '服务器内部错误'}), 500

# ==================== 数据库模型 ====================
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=local_now)
    last_login = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    is_active = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'last_login_ip': self.last_login_ip,
            'is_active': self.is_active
        }

class FileOperation(db.Model):
    __tablename__ = 'file_operations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    username = db.Column(db.String(80))
    operation = db.Column(db.String(50))
    filename = db.Column(db.String(255))
    file_path = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=local_now)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.String(500), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    target_path = db.Column(db.String(500), nullable=True)

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip_address = db.Column(db.String(45))
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=local_now)
    user_agent = db.Column(db.String(255))

# ==================== 辅助函数 ====================
def validate_password(password):
    errors = []
    if len(password) < app.config['PASSWORD_MIN_LENGTH']:
        errors.append(f"密码长度至少需要{app.config['PASSWORD_MIN_LENGTH']}个字符")
    if app.config['PASSWORD_REQUIRE_UPPERCASE'] and not any(c.isupper() for c in password):
        errors.append("密码需要包含至少一个大写字母")
    if app.config['PASSWORD_REQUIRE_LOWERCASE'] and not any(c.islower() for c in password):
        errors.append("密码需要包含至少一个小写字母")
    if app.config['PASSWORD_REQUIRE_DIGITS'] and not any(c.isdigit() for c in password):
        errors.append("密码需要包含至少一个数字")
    return errors

def log_file_operation(user_id, username, operation, filename, file_path=None, success=True, error_message=None, file_size=None, target_path=None):
    try:
        op = FileOperation(
            user_id=user_id,
            username=username,
            operation=operation,
            filename=filename,
            file_path=file_path,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None,
            success=success,
            error_message=error_message,
            file_size=file_size,
            target_path=target_path
        )
        db.session.add(op)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log file operation: {str(e)}")
        db.session.rollback()

def log_login_attempt(username, success):
    try:
        attempt = LoginAttempt(
            username=username,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None,
            success=success
        )
        db.session.add(attempt)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log login attempt: {str(e)}")
        db.session.rollback()

def check_login_lockout(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return False
    if user.locked_until and user.locked_until > local_now():
        return True
    if user.locked_until and user.locked_until <= local_now():
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
    return False

def increment_failed_login(username):
    user = User.query.filter_by(username=username).first()
    if user:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = local_now() + datetime.timedelta(minutes=15)
            logger.warning(f"User {username} locked until {user.locked_until}")
        db.session.commit()

def reset_failed_login(username):
    user = User.query.filter_by(username=username).first()
    if user:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()

def safe_path_join(base_dir, user_path):
    if not user_path or user_path.strip() == '' or user_path.strip() == '/':
        return base_dir
    if user_path.startswith('/'):
        user_path = user_path[1:]
    full_path = os.path.normpath(os.path.join(base_dir, user_path))
    base_dir_real = os.path.realpath(base_dir)
    full_path_real = os.path.realpath(full_path)
    if not full_path_real.startswith(base_dir_real):
        raise APIError("无效的路径", 403)
    return full_path_real

def allowed_file(filename):
    return True

def is_valid_folder_name(folder_name):
    if not folder_name or not folder_name.strip():
        return False, "文件夹名称不能为空"
    illegal_chars = '<>:"/\\|?*'
    for char in illegal_chars:
        if char in folder_name:
            return False, f"文件夹名称不能包含字符: {char}"
    if len(folder_name) > 255:
        return False, "文件夹名称不能超过255个字符"
    if folder_name.startswith('.'):
        return False, "文件夹名称不能以点开头"
    return True, ""

def is_valid_filename(filename):
    if not filename or not filename.strip():
        return False, "文件名不能为空"
    illegal_chars = '<>:"/\\|?*'
    for char in illegal_chars:
        if char in filename:
            return False, f"文件名不能包含字符: {char}"
    if len(filename) > 255:
        return False, "文件名不能超过255个字符"
    if filename.startswith('.'):
        return False, "文件名不能以点开头"
    return True, ""

def verify_database():
    try:
        with app.app_context():
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            db_file = os.path.abspath(db_path)
            db_dir = os.path.dirname(db_file)
            os.makedirs(db_dir, exist_ok=True)
            if os.path.exists(db_file):
                if not os.access(db_file, os.R_OK | os.W_OK):
                    return False, f"数据库文件权限不正确"
            else:
                if not os.access(db_dir, os.W_OK):
                    return False, f"数据库目录不可写"
            db.session.execute(db.text('SELECT 1')).fetchall()
            db.session.commit()
            return True, f"数据库连接正常，文件: {db_file}"
    except Exception as e:
        return False, str(e)

# ==================== 认证装饰器 ====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        if session.get('user_id') != 1:
            return jsonify({'error': '需要管理员权限'}), 403
        return f(*args, **kwargs)
    return decorated_function

def filesystem_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not FILESYSTEM_ENABLED:
            return jsonify({'error': '文件系统操作功能未启用（根目录未配置）'}), 403
        return f(*args, **kwargs)
    return decorated_function

def proxy_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not PROXY_ENABLED:
            return jsonify({'error': '代理功能未启用'}), 403
        return f(*args, **kwargs)
    return decorated_function

def file_access_required(f):
    """装饰器：检查文件访问权限"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        
        # 获取文件路径参数
        file_path_param = kwargs.get('file_path') or kwargs.get('folder_path') or kwargs.get('path')
        
        if file_path_param:
            try:
                full_path = safe_path_join(HTML_ROOT_DIR, file_path_param)
                has_access, error_msg = check_file_access(full_path)
                if not has_access:
                    return jsonify({'error': error_msg}), 403
            except APIError as e:
                return jsonify({'error': e.message}), e.status_code
        
        return f(*args, **kwargs)
    return decorated_function

# ==================== HTTP 代理视图 ====================
@app.route('/proxy/<path:target>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@login_required
@proxy_required
@limiter.limit("100 per minute")
def proxy_request(target):
    try:
        method = request.method
        
        upgrade = request.headers.get('Upgrade', '').lower()
        connection = request.headers.get('Connection', '').lower()
        
        if upgrade == 'websocket' and 'upgrade' in connection:
            logger.info(f"WebSocket upgrade request detected, redirecting to Socket.IO")
            response = Response('WebSocket connections must use Socket.IO', status=426)
            response.headers['Upgrade'] = 'websocket'
            response.headers['Connection'] = 'Upgrade'
            response.headers['X-WebSocket-Proxy'] = 'socketio'
            response.headers['X-SocketIO-Endpoint'] = '/socket.io'
            return response
        
        if method == 'OPTIONS':
            response = Response()
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Proxy-User, X-User-ID, Accept'
            return response
        
        headers = {}
        excluded_headers = ['host', 'connection', 'content-length', 'transfer-encoding', 'accept-encoding']
        
        for key, value in request.headers:
            if key.lower() not in excluded_headers:
                headers[key] = value
        
        headers['X-Proxy-User'] = session.get('username', 'unknown')
        headers['X-Proxy-User-ID'] = str(session.get('user_id', '0'))
        
        query_params = request.args.to_dict()
        data = request.get_data() if request.get_data() else None
        
        target_url = target
        if target_url.startswith('http/'):
            target_url = 'http://' + target_url[5:]
        elif target_url.startswith('https/'):
            target_url = 'https://' + target_url[6:]
        elif not target_url.startswith('http://') and not target_url.startswith('https://'):
            target_url = 'http://' + target_url
        
        is_allowed = False
        for allowed_target in PROXY_ALLOWED_TARGETS:
            if target_url.startswith(allowed_target):
                is_allowed = True
                break
        
        if not is_allowed:
            return jsonify({'error': '不允许代理到此目标地址', 'allowed_targets': PROXY_ALLOWED_TARGETS}), 403
        
        is_stream_request = False
        accept_header = request.headers.get('Accept', '')
        is_sse_request = 'text/event-stream' in accept_header or 'application/x-ndjson' in accept_header
        
        if method in ['POST', 'PUT', 'PATCH'] and data:
            try:
                if isinstance(data, bytes):
                    body_json = json.loads(data.decode('utf-8'))
                else:
                    body_json = request.get_json(silent=True)
                if body_json and body_json.get('stream') == True:
                    is_stream_request = True
                    logger.info(f"Detected stream=true in request body for {target_url}")
            except:
                pass
        
        logger.info(f"User {session.get('username')} proxy {method} request to {target_url}, stream={is_stream_request or is_sse_request}")
        
        try:
            if is_stream_request or is_sse_request:
                req = requests.Request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    params=query_params,
                    data=data if isinstance(data, bytes) else (data.encode('utf-8') if data else None)
                )
                prepared = req.prepare()
                
                session_req = requests.Session()
                response = session_req.send(
                    prepared,
                    stream=True,
                    timeout=60,
                    verify=False
                )
                
                def generate():
                    try:
                        for chunk in response.iter_content(chunk_size=256, decode_unicode=False):
                            if chunk:
                                yield chunk
                    except GeneratorExit:
                        logger.info(f"Stream client disconnected for {target_url}")
                    except Exception as e:
                        logger.error(f"Stream generation error: {e}")
                    finally:
                        response.close()
                        session_req.close()
                
                response_headers = {
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0',
                    'X-Accel-Buffering': 'no',
                    'X-Content-Type-Options': 'nosniff'
                }
                
                for key, value in response.headers.items():
                    key_lower = key.lower()
                    if key_lower in ['content-type', 'cache-control']:
                        continue
                    if key_lower not in ['content-encoding', 'transfer-encoding', 'connection', 'content-length']:
                        response_headers[key] = value
                
                if is_sse_request:
                    response_headers['Content-Type'] = 'text/event-stream'
                elif response.headers.get('Content-Type'):
                    response_headers['Content-Type'] = response.headers['Content-Type']
                
                return Response(
                    stream_with_context(generate()),
                    status=response.status_code,
                    headers=response_headers,
                    direct_passthrough=True
                )
            else:
                response = requests.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    params=query_params,
                    data=data,
                    timeout=30,
                    allow_redirects=True,
                    verify=False
                )
                
                response_headers = {}
                excluded_response_headers = ['content-encoding', 'transfer-encoding', 'connection']
                for key, value in response.headers.items():
                    if key.lower() not in excluded_response_headers:
                        response_headers[key] = value
                
                return Response(response.content, status=response.status_code, headers=response_headers)
            
        except requests.exceptions.Timeout:
            return jsonify({'error': '代理请求超时'}), 504
        except requests.exceptions.ConnectionError:
            return jsonify({'error': f'无法连接到目标服务: {target_url}'}), 502
        except requests.exceptions.RequestException as e:
            return jsonify({'error': f'代理请求失败: {str(e)}'}), 500
            
    except Exception as e:
        logger.error(f"Proxy error: {str(e)}")
        return jsonify({'error': f'代理处理失败: {str(e)}'}), 500

# ==================== 代理状态接口 ====================
@app.route('/api/proxy/status', methods=['GET'])
@login_required
def get_proxy_status():
    return jsonify({
        'enabled': PROXY_ENABLED,
        'allowed_targets': PROXY_ALLOWED_TARGETS,
        'user': session.get('username', 'unknown'),
        'websocket_supported': True,
        'stream_supported': True
    })

@app.route('/api/proxy/test', methods=['POST'])
@login_required
@proxy_required
def test_proxy_target():
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({'error': '请提供目标地址'}), 400
        
        target = data['target']
        
        is_allowed = False
        for allowed_target in PROXY_ALLOWED_TARGETS:
            if target.startswith(allowed_target):
                is_allowed = True
                break
        
        if not is_allowed:
            return jsonify({'error': '目标地址不在白名单中', 'allowed_targets': PROXY_ALLOWED_TARGETS}), 403
        
        if target.startswith('ws://') or target.startswith('wss://'):
            try:
                ws = websocket.create_connection(target, timeout=5)
                ws.close()
                return jsonify({'success': True, 'target': target, 'type': 'websocket', 'message': 'WebSocket服务可达'})
            except Exception as e:
                return jsonify({'success': False, 'target': target, 'type': 'websocket', 'error': str(e)}), 502
        else:
            try:
                response = requests.head(target, timeout=5, verify=False)
                return jsonify({'success': True, 'target': target, 'type': 'http', 'status_code': response.status_code, 'message': f'目标服务可达，响应状态码: {response.status_code}'})
            except Exception as e:
                return jsonify({'success': False, 'target': target, 'type': 'http', 'error': str(e)}), 502
            
    except Exception as e:
        logger.error(f"Proxy test error: {str(e)}")
        return jsonify({'error': f'测试失败: {str(e)}'}), 500

# ==================== 文件列表接口 ====================
@app.route('/api/filelist', methods=['GET'])
@filesystem_required
def get_file_list():
    """获取指定目录下的文件列表"""
    try:
        requested_path = request.args.get('path', '')
        
        if 'user_id' not in session:
            if requested_path and requested_path.strip():
                check_path = requested_path.strip().lstrip('/').replace('\\', '/')
                if check_path == 'users' or check_path.startswith('users/'):
                    return jsonify({
                        'success': False, 
                        'error': '请先登录后访问 users 目录',
                        'require_login': True
                    }), 401
            path = requested_path if requested_path else ''
        else:
            accessible_path, redirect_msg = get_user_accessible_path(requested_path)
            if redirect_msg and requested_path and accessible_path != requested_path:
                logger.info(f"Redirecting user {session['username']} from {requested_path} to {accessible_path}")
            path = accessible_path
        
        full_path = safe_path_join(HTML_ROOT_DIR, path)
        
        if not os.path.exists(full_path):
            raise APIError(f'目录不存在: {full_path}', 404)
        
        if not os.path.isdir(full_path):
            raise APIError(f'路径不是一个目录: {full_path}', 400)
        
        items = []
        for item in os.listdir(full_path):
            item_path = os.path.join(full_path, item)
            
            if item == '__pycache__':
                continue
            
            if 'user_id' not in session:
                if item == 'users':
                    continue
                if path == '' and item.startswith('.'):
                    continue
            
            item_stat = os.stat(item_path)
            is_dir = os.path.isdir(item_path)
            
            if path:
                item_rel_path = os.path.join(path, item)
            else:
                item_rel_path = item
            
            size = 0
            if not is_dir:
                size = item_stat.st_size
            
            modified_time = datetime.datetime.fromtimestamp(item_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            
            # 判断文件类型
            file_type = 'file'
            if is_dir:
                file_type = 'dir'
            elif is_video_file(item):
                file_type = 'video'
            elif is_audio_file(item):
                file_type = 'audio'
            
            items.append({
                'name': item,
                'type': file_type,
                'path': item_rel_path,
                'size': size,
                'modified': modified_time,
                'permissions': oct(item_stat.st_mode)[-3:],
                'owner_uid': item_stat.st_uid,
                'owner_gid': item_stat.st_gid,
                'is_video': is_video_file(item),
                'is_audio': is_audio_file(item),
                'mime_type': get_media_mime_type(item) if is_media_file(item) else None
            })
        
        items.sort(key=lambda x: (x['type'] != 'dir', x['name'].lower()))
        
        response_data = {
            'success': True,
            'path': path or '/',
            'parent_path': os.path.dirname(path) if path and os.path.dirname(path) != '/' else '',
            'items': items,
            'total_items': len(items),
            'total_dirs': sum(1 for item in items if item['type'] == 'dir'),
            'total_files': sum(1 for item in items if item['type'] in ['file', 'video', 'audio']),
            'total_videos': sum(1 for item in items if item['type'] == 'video'),
            'total_audios': sum(1 for item in items if item['type'] == 'audio')
        }
        
        if 'user_id' in session:
            response_data['is_admin'] = session.get('user_id') == 1
            response_data['username'] = session.get('username')
        else:
            response_data['is_admin'] = False
            response_data['username'] = None
        
        return jsonify(response_data)
        
    except APIError as e:
        return jsonify({'error': e.message}), e.status_code
    except Exception as e:
        logger.error(f"Get file list error: {str(e)}")
        return jsonify({'error': f'获取文件列表失败: {str(e)}'}), 500

# ==================== 视频文件播放接口 ====================
@app.route('/video/<path:file_path>', methods=['GET'])
@filesystem_required
def stream_video(file_path):
    """视频文件流式播放，支持Range请求"""
    try:
        full_path = safe_path_join(HTML_ROOT_DIR, file_path)
        
        # 检查用户权限
        if 'user_id' in session:
            has_access, error_msg = check_file_access(full_path, 'read')
            if not has_access:
                return jsonify({'error': error_msg}), 403
        else:
            # 未登录用户不能访问 users 目录
            if 'users' in file_path.replace('\\', '/').split('/'):
                return jsonify({'error': '请先登录后访问 users 目录'}), 401
        
        if not os.path.exists(full_path):
            raise APIError(f'文件不存在: {file_path}', 404)
        
        if not os.path.isfile(full_path):
            raise APIError(f'路径不是文件: {file_path}', 400)
        
        if not is_video_file(full_path) and not is_audio_file(full_path):
            raise APIError(f'不支持的文件类型: {file_path}', 400)
        
        file_size = os.path.getsize(full_path)
        file_name = os.path.basename(full_path)
        mime_type = get_media_mime_type(full_path)
        
        # 处理Range请求（支持视频拖动）
        range_header = request.headers.get('Range', None)
        
        if range_header:
            # 解析Range请求
            byte_range = range_header.replace('bytes=', '').split('-')
            start = int(byte_range[0]) if byte_range[0] else 0
            end = int(byte_range[1]) if len(byte_range) > 1 and byte_range[1] else file_size - 1
            
            if start >= file_size:
                return jsonify({'error': '请求范围超出文件大小'}), 416
            
            length = end - start + 1
            
            # 读取指定范围的数据
            with open(full_path, 'rb') as f:
                f.seek(start)
                data = f.read(length)
            
            # 记录播放操作
            if 'user_id' in session:
                log_file_operation(
                    user_id=session['user_id'],
                    username=session['username'],
                    operation='stream_video',
                    filename=file_name,
                    file_path=full_path,
                    file_size=file_size
                )
            
            response = Response(
                data,
                206,  # Partial Content
                mimetype=mime_type,
                direct_passthrough=True
            )
            response.headers.add('Content-Range', f'bytes {start}-{end}/{file_size}')
            response.headers.add('Accept-Ranges', 'bytes')
            response.headers.add('Content-Length', str(length))
            response.headers.add('Cache-Control', 'no-cache')
            
            return response
        else:
            # 完整文件请求
            # 记录播放操作
            if 'user_id' in session:
                log_file_operation(
                    user_id=session['user_id'],
                    username=session['username'],
                    operation='play_video',
                    filename=file_name,
                    file_path=full_path,
                    file_size=file_size
                )
            
            return send_file(
                full_path,
                mimetype=mime_type,
                as_attachment=False,
                download_name=file_name,
                conditional=True
            )
        
    except APIError as e:
        return jsonify({'error': e.message}), e.status_code
    except Exception as e:
        logger.error(f"Video streaming error: {str(e)}")
        return jsonify({'error': f'视频播放失败: {str(e)}'}), 500

@app.route('/api/video/info/<path:file_path>', methods=['GET'])
@filesystem_required
def get_video_info(file_path):
    """获取视频文件信息"""
    try:
        full_path = safe_path_join(HTML_ROOT_DIR, file_path)
        
        # 检查用户权限
        if 'user_id' in session:
            has_access, error_msg = check_file_access(full_path, 'read')
            if not has_access:
                return jsonify({'error': error_msg}), 403
        
        if not os.path.exists(full_path):
            raise APIError(f'文件不存在: {file_path}', 404)
        
        if not os.path.isfile(full_path):
            raise APIError(f'路径不是文件: {file_path}', 400)
        
        file_size = os.path.getsize(full_path)
        file_name = os.path.basename(full_path)
        file_ext = os.path.splitext(full_path)[1].lower()
        
        # 获取文件修改时间
        modified_time = datetime.datetime.fromtimestamp(os.path.getmtime(full_path))
        
        video_info = {
            'success': True,
            'name': file_name,
            'path': file_path,
            'size': file_size,
            'size_mb': round(file_size / (1024 * 1024), 2),
            'extension': file_ext,
            'mime_type': get_media_mime_type(full_path),
            'is_video': is_video_file(full_path),
            'is_audio': is_audio_file(full_path),
            'modified': modified_time.strftime('%Y-%m-%d %H:%M:%S'),
            'stream_url': f'/video/{file_path}',
            'download_url': f'/download/{file_path}' if 'user_id' in session else None
        }
        
        return jsonify(video_info)
        
    except APIError as e:
        return jsonify({'error': e.message}), e.status_code
    except Exception as e:
        logger.error(f"Get video info error: {str(e)}")
        return jsonify({'error': f'获取视频信息失败: {str(e)}'}), 500

# ==================== 视频文件API端点 ====================
@app.route('/api/videos', methods=['GET'])
@filesystem_required
def get_video_list():
    """获取所有视频文件列表"""
    try:
        path = request.args.get('path', '')
        
        if 'user_id' not in session:
            if path and 'users' in path.replace('\\', '/').split('/'):
                return jsonify({'error': '请先登录后访问 users 目录'}), 401
        
        full_path = safe_path_join(HTML_ROOT_DIR, path) if path else HTML_ROOT_DIR
        
        if not os.path.exists(full_path):
            raise APIError(f'目录不存在: {path}', 404)
        
        videos = []
        
        for root, dirs, files in os.walk(full_path):
            # 跳过__pycache__目录
            dirs[:] = [d for d in dirs if d != '__pycache__']
            
            for file in files:
                if is_video_file(file):
                    file_full_path = os.path.join(root, file)
                    file_rel_path = os.path.relpath(file_full_path, HTML_ROOT_DIR)
                    file_size = os.path.getsize(file_full_path)
                    modified_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_full_path))
                    
                    videos.append({
                        'name': file,
                        'path': file_rel_path,
                        'size': file_size,
                        'size_mb': round(file_size / (1024 * 1024), 2),
                        'extension': os.path.splitext(file)[1].lower(),
                        'mime_type': get_media_mime_type(file),
                        'modified': modified_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'stream_url': f'/video/{file_rel_path}',
                    })
        
        # 按修改时间排序
        videos.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({
            'success': True,
            'videos': videos,
            'total': len(videos)
        })
        
    except APIError as e:
        return jsonify({'error': e.message}), e.status_code
    except Exception as e:
        logger.error(f"Get video list error: {str(e)}")
        return jsonify({'error': f'获取视频列表失败: {str(e)}'}), 500

# ==================== serve_html 路由 ====================
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
@filesystem_required
def serve_html(path=''):
    try:
        if 'user_id' in session:
            accessible_path, redirect_msg = get_user_accessible_path(path)
            if redirect_msg and path and accessible_path != path:
                return redirect(f'/{accessible_path}')
            real_path = safe_path_join(HTML_ROOT_DIR, accessible_path)
        else:
            if path and path.strip():
                check_path = path.strip().lstrip('/').replace('\\', '/')
                if check_path == 'users' or check_path.startswith('users/'):
                    return jsonify({
                        'error': '请先登录后访问 users 目录', 
                        'require_login': True
                    }), 401
            real_path = safe_path_join(HTML_ROOT_DIR, path if path else '')
        
        if not os.path.exists(real_path):
            return "路径不存在", 404
        
        if os.path.isfile(real_path):
            if request.args.get('download') == 'true':
                if 'user_id' not in session:
                    return jsonify({'error': '请先登录后下载文件'}), 401
                
                has_access, error_msg = check_file_access(real_path, 'download')
                if not has_access:
                    return jsonify({'error': error_msg}), 403
                
                log_file_operation(
                    user_id=session['user_id'],
                    username=session['username'],
                    operation='download',
                    filename=os.path.basename(real_path),
                    file_path=real_path,
                    file_size=os.path.getsize(real_path)
                )
                
                return send_file(
                    real_path,
                    as_attachment=True,
                    download_name=os.path.basename(real_path),
                    mimetype='application/octet-stream'
                )
            else:
                # 如果是视频文件，重定向到视频流播放页面
                if is_video_file(real_path) or is_audio_file(real_path):
                    # 读取视频播放器模板
                    player_template_path = os.path.join(os.path.dirname(__file__), 'templates', 'video_player.html')
                    
                    if os.path.exists(player_template_path):
                        with open(player_template_path, 'r', encoding='utf-8') as f:
                            player_html = f.read()
                        
                        # 获取文件信息
                        file_size = os.path.getsize(real_path)
                        file_name = os.path.basename(real_path)
                        mime_type = get_media_mime_type(real_path)
                        
                        # 注入视频信息
                        video_data = {
                            'name': file_name,
                            'path': path,
                            'size': file_size,
                            'size_mb': round(file_size / (1024 * 1024), 2),
                            'mime_type': mime_type,
                            'is_video': is_video_file(real_path),
                            'is_audio': is_audio_file(real_path),
                            'stream_url': f'/video/{path}',
                            'download_url': f'/{path}?download=true' if 'user_id' in session else None
                        }
                        
                        script_tag = f'''
                        <script>
                            window.__VIDEO_DATA__ = {json.dumps(video_data, ensure_ascii=False)};
                        </script>
                        </head>
                        '''
                        
                        if '</head>' in player_html:
                            rendered_html = player_html.replace('</head>', script_tag)
                        else:
                            rendered_html = script_tag.replace('</head>', '') + player_html
                        
                        return Response(rendered_html, mimetype='text/html')
                    else:
                        # 如果没有播放器模板，直接返回视频文件
                        return send_file(real_path, mimetype=mime_type)
                
                # 对于其他文件类型，直接返回文件内容
                with open(real_path, 'rb') as f:
                    file_content = f.read()
                
                file_ext = os.path.splitext(real_path)[1].lower()
                mime_types = {
                    '.html': 'text/html',
                    '.js': 'application/javascript',
                    '.css': 'text/css',
                    '.json': 'application/json',
                    '.png': 'image/png',
                    '.jpg': 'image/jpeg',
                    '.jpeg': 'image/jpeg',
                    '.gif': 'image/gif',
                    '.txt': 'text/plain',
                    '.pdf': 'application/pdf',
                    '.svg': 'image/svg+xml',
                    '.ico': 'image/x-icon',
                    '.woff': 'font/woff',
                    '.woff2': 'font/woff2',
                    '.ttf': 'font/ttf',
                    '.mp4': 'video/mp4',
                    '.mp3': 'audio/mpeg',
                    '.webm': 'video/webm',
                }
                return Response(file_content, mimetype=mime_types.get(file_ext, 'application/octet-stream'))
        
        view_template_path = os.path.join(HTML_ROOT_DIR, '__view.html')
        
        if not os.path.exists(view_template_path):
            items = []
            for item in os.listdir(real_path):
                item_path = os.path.join(real_path, item)
                if 'user_id' not in session:
                    if item == 'users' or item.startswith('.'):
                        continue
                
                item_rel_path = os.path.join(path, item) if path else item
                
                item_type = 'file'
                if os.path.isdir(item_path):
                    item_type = 'dir'
                elif is_video_file(item):
                    item_type = 'video'
                elif is_audio_file(item):
                    item_type = 'audio'
                
                items.append({
                    'name': item,
                    'type': item_type,
                    'path': item_rel_path,
                    'size': os.path.getsize(item_path) if os.path.isfile(item_path) else 0,
                    'modified': datetime.datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%Y-%m-%d %H:%M:%S'),
                    'is_video': is_video_file(item),
                    'is_audio': is_audio_file(item)
                })
            return jsonify(items)
        
        with open(view_template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        items = []
        for item in os.listdir(real_path):
            item_path = os.path.join(real_path, item)
            
            if 'user_id' not in session:
                if item == 'users' or item.startswith('.'):
                    continue
            
            if path:
                item_rel_path = os.path.join(path, item)
            else:
                item_rel_path = item
            
            item_type = 'file'
            if os.path.isdir(item_path):
                item_type = 'dir'
            elif is_video_file(item):
                item_type = 'video'
            elif is_audio_file(item):
                item_type = 'audio'
            
            items.append({
                'name': item,
                'type': item_type,
                'path': item_rel_path,
                'size': os.path.getsize(item_path) if os.path.isfile(item_path) else 0,
                'modified': datetime.datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%Y-%m-%d %H:%M:%S'),
                'is_video': is_video_file(item),
                'is_audio': is_audio_file(item),
                'mime_type': get_media_mime_type(item) if is_media_file(item) else None
            })
        
        items.sort(key=lambda x: (x['type'] != 'dir', x['name'].lower()))
        
        initial_data = {
            'currentPath': path or '',
            'files': items,
            'parentPath': os.path.dirname(path) if path and os.path.dirname(path) != '/' else '',
            'filesystemEnabled': FILESYSTEM_ENABLED,
            'isAuthenticated': 'user_id' in session,
            'username': session.get('username', ''),
            'isAdmin': session.get('user_id') == 1 if 'user_id' in session else False,
            'proxyEnabled': PROXY_ENABLED,
            'proxyAllowedTargets': PROXY_ALLOWED_TARGETS,
            'websocketEndpoint': '/socket.io',
            'videoSupported': True,
            'audioSupported': True
        }
        
        script_tag = f'''
        <script>
            window.__INITIAL_DATA__ = {json.dumps(initial_data, ensure_ascii=False)};
        </script>
        </head>
        '''
        
        if '</head>' in template_content:
            rendered_html = template_content.replace('</head>', script_tag)
        else:
            rendered_html = script_tag.replace('</head>', '') + template_content
        
        return Response(rendered_html, mimetype='text/html')
        
    except APIError as e:
        return str(e), e.status_code
    except Exception as e:
        logger.error(f"Error serving path {path}: {str(e)}")
        return "服务器内部错误", 500

# ==================== 健康检查和系统状态 ====================
@app.route('/health', methods=['GET'])
def health_check():
    try:
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        db_file = os.path.abspath(db_path)
        db_dir = os.path.dirname(db_file)
        
        try:
            from sqlalchemy import text
            db.session.execute(text('SELECT 1')).fetchall()
            db.session.commit()
            db_connection = 'connected'
            db_message = '数据库连接正常'
            db_status_badge = 'success'
        except Exception as e:
            db_connection = f'error: {str(e)}'
            db_message = f'连接失败: {str(e)}'
            db_status_badge = 'error'
        
        is_https = request.is_secure or request.headers.get('X-Forwarded-Proto', '') == 'https'
        
        return jsonify({
            'status': 'healthy',
            'timestamp': local_now().isoformat(),
            'filesystem': {
                'enabled': FILESYSTEM_ENABLED, 
                'root': HTML_ROOT_DIR if FILESYSTEM_ENABLED else None
            },
            'database': {
                'status': db_connection,
                'status_badge': db_status_badge,
                'message': db_message,
                'path': db_file,
                'directory': {
                    'exists': os.path.exists(db_dir),
                    'writable': os.access(db_dir, os.W_OK) if os.path.exists(db_dir) else False
                } if db_dir else None,
                'file': {
                    'exists': os.path.exists(db_file),
                    'writable': os.access(db_file, os.W_OK) if os.path.exists(db_file) else False
                } if db_file else None
            },
            'proxy': {
                'enabled': PROXY_ENABLED, 
                'allowed_targets': PROXY_ALLOWED_TARGETS, 
                'websocket_supported': True
            },
            'ssl': {
                'enabled': SSL_ENABLED or is_https,
                'cert_file': SSL_CERT_FILE if SSL_ENABLED else None,
                'key_file': SSL_KEY_FILE if SSL_ENABLED else None,
                'is_https': is_https,
                'message': 'HTTPS已启用' if is_https else ('SSL已配置' if SSL_ENABLED else 'HTTP（未启用SSL）')
            },
            'media': {
                'video_formats': list(VIDEO_MIME_TYPES.keys()),
                'audio_formats': list(AUDIO_MIME_TYPES.keys()),
                'streaming_supported': True,
                'range_requests_supported': True
            }
        })
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return jsonify({
            'status': 'unhealthy', 
            'error': str(e),
            'timestamp': local_now().isoformat(),
            'ssl': {
                'enabled': SSL_ENABLED
            }
        }), 500

@app.route('/api/filesystem-status', methods=['GET'])
def get_filesystem_status():
    return jsonify({
        'enabled': FILESYSTEM_ENABLED, 
        'root': HTML_ROOT_DIR if FILESYSTEM_ENABLED else None,
        'video_supported': True,
        'video_formats': list(VIDEO_MIME_TYPES.keys())
    })

# ==================== 用户管理 API ====================
@app.route('/api/register', methods=['POST'])
@admin_required
@limiter.limit("10 per hour")
def register():
    try:
        data = request.get_json()
        if not data:
            raise APIError('请提供JSON格式的数据', 400)
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            raise APIError('请提供用户名和密码', 400)
        
        if len(username) < 3:
            raise APIError('用户名至少需要3个字符', 400)
        
        password_errors = validate_password(password)
        if password_errors:
            return jsonify({'errors': password_errors}), 400
        
        if User.query.filter_by(username=username).first():
            raise APIError('用户名已存在', 400)
        
        new_user = User(username=username)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        user_folder = os.path.join(HTML_ROOT_DIR, 'users', username)
        os.makedirs(user_folder, exist_ok=True)
        logger.info(f"Created user folder for {username}: {user_folder}")
        
        logger.info(f"Admin {session['username']} created new user: {username}")
        
        return jsonify({'status': 'success', 'message': f'用户 {username} 创建成功', 'user': new_user.to_dict()}), 201
        
    except APIError as e:
        raise e
    except Exception as e:
        db.session.rollback()
        logger.error(f"User registration error: {str(e)}")
        raise APIError(f'创建用户失败', 500)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        if not data:
            raise APIError('请提供JSON格式的数据', 400)
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            raise APIError('请提供用户名和密码', 400)
        
        if check_login_lockout(username):
            log_login_attempt(username, False)
            raise APIError('账户已被临时锁定，请15分钟后再试', 403)
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            increment_failed_login(username)
            log_login_attempt(username, False)
            logger.warning(f"Failed login attempt for user {username}")
            raise APIError('用户名或密码错误', 401)
        
        if not user.is_active:
            log_login_attempt(username, False)
            raise APIError('账号已被禁用', 403)
        
        reset_failed_login(username)
        user.last_login = local_now()
        user.last_login_ip = request.remote_addr
        db.session.commit()
        log_login_attempt(username, True)
        
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = (user.id == 1)
        
        if user.id != 1:
            user_folder = os.path.join(HTML_ROOT_DIR, 'users', username)
            os.makedirs(user_folder, exist_ok=True)
        
        default_path = f"users/{username}" if user.id != 1 else ""
        
        return jsonify({
            'status': 'success',
            'message': '登录成功',
            'user': user.to_dict(),
            'is_admin': (user.id == 1),
            'default_path': default_path,
            'filesystem_enabled': FILESYSTEM_ENABLED,
            'proxy_enabled': PROXY_ENABLED
        })
        
    except APIError as e:
        raise e
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise APIError(f'登录失败: {str(e)}', 500)

@app.route('/api/logout', methods=['POST'])
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    return jsonify({'status': 'success', 'message': '已成功登出'})

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            default_path = f"users/{user.username}" if user.id != 1 else ""
            return jsonify({
                'authenticated': True,
                'user': user.to_dict(),
                'is_admin': (user.id == 1),
                'default_path': default_path,
                'filesystem_enabled': FILESYSTEM_ENABLED,
                'proxy_enabled': PROXY_ENABLED,
                'can_access_users': True
            })
    
    return jsonify({
        'authenticated': False, 
        'is_admin': False, 
        'filesystem_enabled': FILESYSTEM_ENABLED, 
        'proxy_enabled': PROXY_ENABLED,
        'can_access_users': False,
        'message': '未登录用户只能浏览公开文件'
    })

@app.route('/api/change-password', methods=['POST'])
@login_required
@limiter.limit("3 per hour")
def change_password():
    try:
        data = request.get_json()
        if not data:
            raise APIError('请提供JSON格式的数据', 400)
        
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        
        if not old_password or not new_password:
            raise APIError('请提供旧密码和新密码', 400)
        
        password_errors = validate_password(new_password)
        if password_errors:
            return jsonify({'errors': password_errors}), 400
        
        user = User.query.get(session['user_id'])
        
        if not user.check_password(old_password):
            raise APIError('旧密码错误', 401)
        
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': '密码修改成功'})
        
    except APIError as e:
        raise e
    except Exception as e:
        db.session.rollback()
        logger.error(f"Password change error: {str(e)}")
        raise APIError(f'密码修改失败', 500)

@app.route('/api/admin/users/<int:user_id>/password', methods=['POST'])
@admin_required
@limiter.limit("10 per hour")
def admin_change_password(user_id):
    try:
        data = request.get_json()
        if not data:
            raise APIError('请提供JSON格式的数据', 400)
        
        new_password = data.get('new_password')
        if not new_password:
            raise APIError('请提供新密码', 400)
        
        password_errors = validate_password(new_password)
        if password_errors:
            return jsonify({'errors': password_errors}), 400
        
        user = User.query.get(user_id)
        if not user:
            raise APIError('用户不存在', 404)
        
        if user_id == session['user_id']:
            raise APIError('请使用普通修改密码接口修改自己的密码', 400)
        
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': f'用户 {user.username} 的密码已修改成功'})
        
    except APIError as e:
        raise e
    except Exception as e:
        db.session.rollback()
        logger.error(f"Admin password change error: {str(e)}")
        raise APIError(f'密码修改失败', 500)

@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    try:
        users = User.query.all()
        return jsonify({'success': True, 'users': [user.to_dict() for user in users]})
    except Exception as e:
        logger.error(f"Get users error: {str(e)}")
        raise APIError(f'获取用户列表失败', 500)

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    try:
        if user_id == 1:
            raise APIError('不能删除管理员账户', 403)
        if user_id == session['user_id']:
            raise APIError('不能删除当前登录的账户', 403)
        
        user = User.query.get_or_404(user_id)
        
        user_folder = os.path.join(HTML_ROOT_DIR, 'users', user.username)
        if os.path.exists(user_folder):
            try:
                shutil.rmtree(user_folder)
                logger.info(f"Deleted user folder for {user.username}")
            except Exception as e:
                logger.warning(f"Failed to delete user folder {user_folder}: {e}")
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'用户 {user.username} 已删除'})
    except APIError as e:
        raise e
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete user error: {str(e)}")
        raise APIError(f'删除用户失败', 500)

@app.route('/api/users/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
def toggle_user_status(user_id):
    try:
        if user_id == 1:
            raise APIError('不能禁用管理员账户', 403)
        
        user = User.query.get_or_404(user_id)
        user.is_active = not user.is_active
        db.session.commit()
        
        status_text = "启用" if user.is_active else "禁用"
        return jsonify({'success': True, 'message': f'用户 {user.username} 已{status_text}', 'user': user.to_dict()})
    except APIError as e:
        raise e
    except Exception as e:
        db.session.rollback()
        logger.error(f"Toggle user status error: {str(e)}")
        raise APIError(f'操作失败', 500)

# ==================== 文件管理 API ====================
@app.route('/api/files', methods=['GET'])
@login_required
@filesystem_required
def get_files():
    try:
        if session.get('user_id') != 1:
            user_folder = os.path.join(HTML_ROOT_DIR, 'users', session['username'])
            if os.path.exists(user_folder):
                files = []
                for item in os.listdir(user_folder):
                    item_path = os.path.join(user_folder, item)
                    if os.path.isfile(item_path):
                        file_type = 'video' if is_video_file(item) else ('audio' if is_audio_file(item) else 'file')
                        files.append({
                            'name': item,
                            'size': os.path.getsize(item_path),
                            'modified': datetime.datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%Y-%m-%d %H:%M:%S'),
                            'type': file_type,
                            'full_path': f'/users/{session["username"]}/{item}',
                            'is_video': is_video_file(item),
                            'is_audio': is_audio_file(item)
                        })
                    elif os.path.isdir(item_path) and item != '__pycache__':
                        files.append({
                            'name': item,
                            'size': 0,
                            'modified': datetime.datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%Y-%m-%d %H:%M:%S'),
                            'type': 'dir',
                            'full_path': f'/users/{session["username"]}/{item}'
                        })
                files.sort(key=lambda x: (x['type'] != 'dir', x['name'].lower()))
                return jsonify({'success': True, 'files': files})
            else:
                return jsonify({'success': True, 'files': []})
        
        files = []
        for item in os.listdir(HTML_ROOT_DIR):
            item_path = os.path.join(HTML_ROOT_DIR, item)
            if os.path.isfile(item_path):
                file_type = 'video' if is_video_file(item) else ('audio' if is_audio_file(item) else 'file')
                files.append({
                    'name': item,
                    'size': os.path.getsize(item_path),
                    'modified': datetime.datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%Y-%m-%d %H:%M:%S'),
                    'type': file_type,
                    'is_video': is_video_file(item),
                    'is_audio': is_audio_file(item)
                })
            elif os.path.isdir(item_path) and item != '__pycache__':
                files.append({
                    'name': item,
                    'size': 0,
                    'modified': datetime.datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%Y-%m-%d %H:%M:%S'),
                    'type': 'dir'
                })
        
        files.sort(key=lambda x: (x['type'] != 'dir', x['name'].lower()))
        return jsonify({'success': True, 'files': files})
    except Exception as e:
        logger.error(f"Get files error: {str(e)}")
        raise APIError(f'获取文件列表失败: {str(e)}', 500)

# ==================== 审计日志 API ====================
@app.route('/api/audit/file-operations', methods=['GET'])
@admin_required
def get_file_audit_logs():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        query = FileOperation.query.order_by(FileOperation.timestamp.desc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'success': True,
            'logs': [{
                'id': log.id,
                'username': log.username,
                'operation': log.operation,
                'filename': log.filename,
                'timestamp': log.timestamp.isoformat(),
                'ip_address': log.ip_address,
                'success': log.success,
                'error_message': log.error_message,
                'file_size': log.file_size
            } for log in pagination.items],
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'pages': pagination.pages
        })
    except Exception as e:
        logger.error(f"Get audit logs error: {str(e)}")
        raise APIError(f'获取审计日志失败', 500)

@app.route('/api/audit/login-attempts', methods=['GET'])
@admin_required
def get_login_audit_logs():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        query = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'success': True,
            'logs': [{
                'id': log.id,
                'username': log.username,
                'ip_address': log.ip_address,
                'success': log.success,
                'timestamp': log.timestamp.isoformat(),
                'user_agent': log.user_agent
            } for log in pagination.items],
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'pages': pagination.pages
        })
    except Exception as e:
        logger.error(f"Get login audit logs error: {str(e)}")
        raise APIError(f'获取登录审计日志失败', 500)

@app.route('/api/stats', methods=['GET'])
@admin_required
def get_system_stats():
    try:
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        
        total_operations = FileOperation.query.count()
        successful_ops = FileOperation.query.filter_by(success=True).count()
        
        since = local_now() - datetime.timedelta(hours=24)
        recent_ops = FileOperation.query.filter(FileOperation.timestamp >= since).count()
        
        total_login_attempts = LoginAttempt.query.count()
        successful_logins = LoginAttempt.query.filter_by(success=True).count()
        failed_logins = LoginAttempt.query.filter_by(success=False).count()
        
        if total_login_attempts > 0:
            success_rate = round((successful_logins / total_login_attempts) * 100, 2)
        else:
            success_rate = 0
        
        logger.info(f"登录统计: 总计={total_login_attempts}, 成功={successful_logins}, 失败={failed_logins}, 成功率={success_rate}%")
        
        storage_stats = {}
        if FILESYSTEM_ENABLED:
            total_size = 0
            file_count = 0
            dir_count = 0
            video_count = 0
            audio_count = 0
            
            for root, dirs, files in os.walk(HTML_ROOT_DIR):
                dir_count += len(dirs)
                file_count += len(files)
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        total_size += os.path.getsize(file_path)
                    except:
                        pass
                    if is_video_file(file):
                        video_count += 1
                    elif is_audio_file(file):
                        audio_count += 1
            
            storage_stats = {
                'total_size': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'file_count': file_count,
                'directory_count': dir_count,
                'video_count': video_count,
                'audio_count': audio_count
            }
        
        return jsonify({
            'success': True,
            'stats': {
                'users': {
                    'total': total_users, 
                    'active': active_users, 
                    'inactive': total_users - active_users
                },
                'file_operations': {
                    'total': total_operations, 
                    'successful': successful_ops, 
                    'failed': total_operations - successful_ops, 
                    'recent_24h': recent_ops
                },
                'login_attempts': {
                    'total': total_login_attempts,
                    'successful': successful_logins,
                    'failed': failed_logins,
                    'success_rate': success_rate
                },
                'filesystem': {
                    'enabled': FILESYSTEM_ENABLED, 
                    'root': HTML_ROOT_DIR if FILESYSTEM_ENABLED else None, 
                    **storage_stats
                },
                'proxy': {
                    'enabled': PROXY_ENABLED, 
                    'allowed_targets': PROXY_ALLOWED_TARGETS, 
                    'websocket_supported': True
                },
                'media': {
                    'video_formats_supported': list(VIDEO_MIME_TYPES.keys()),
                    'audio_formats_supported': list(AUDIO_MIME_TYPES.keys()),
                    'streaming_enabled': True
                }
            }
        })
    except Exception as e:
        logger.error(f"Get stats error: {str(e)}")
        raise APIError(f'获取系统统计信息失败', 500)

# ==================== 数据库初始化 ====================
def init_database():
    with app.app_context():
        db.create_all()
        if User.query.first() is None:
            default_user = User(username='admin')
            default_user.set_password('Admin@123456')
            db.session.add(default_user)
            db.session.commit()
            logger.info("Database initialized with default admin user")
            print("\n" + "="*50)
            print("✅ 数据库初始化完成！")
            print("="*50)
            print("默认管理员账户：")
            print("  📝 用户名: admin")
            print("  🔑 密码: Admin@123456")
            print("="*50)
        else:
            print("\n" + "="*50)
            print("ℹ️  数据库已存在用户，跳过初始化")
            print("="*50 + "\n")

# ==================== 主程序入口 ====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        db_valid, db_message = verify_database()
        if not db_valid:
            logger.warning(f"Database verification failed: {db_message}")
    
    if args.init_db:
        init_database()
        print("\n✅ 数据库初始化完成，程序退出。")
        sys.exit(0)
    
    host = file_config['server']['host']
    port = int(file_config['server']['port'])
    
    print("\n" + "="*60)
    print("🚀 文件浏览器服务器启动")
    print("="*60)
    print(f"服务器地址: {host}:{port}")
    print(f"当前时间: {local_now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"文件系统操作: {'✅ 启用' if FILESYSTEM_ENABLED else '❌ 禁用'}")
    if FILESYSTEM_ENABLED:
        print(f"根目录: {os.path.abspath(HTML_ROOT_DIR)}")
    print(f"文件类型限制: ❌ 已禁用（允许所有文件类型）")
    print(f"代理功能: {'✅ 启用' if PROXY_ENABLED else '❌ 禁用'}")
    if PROXY_ENABLED:
        print(f"允许代理的目标: {', '.join(PROXY_ALLOWED_TARGETS)}")
        print(f"WebSocket代理: ✅ 支持 (通过 Socket.IO)")
    
    # 显示限流状态
    if rate_limit_enabled and limits:
        print(f"限流功能: ✅ 启用 (限制规则: {', '.join(limits)})")
    else:
        print(f"限流功能: ❌ 禁用")
    print("="*60)
    
    print("\n🎬 视频播放功能:")
    print("- ✅ 支持流式播放 (HTTP Range请求)")
    print("- ✅ 支持视频拖动/快进")
    print("- ✅ 支持的视频格式: " + ", ".join(VIDEO_MIME_TYPES.keys()))
    print("- ✅ 支持的音频格式: " + ", ".join(AUDIO_MIME_TYPES.keys()))
    print("- 📹 视频播放路径: /video/{文件路径}")
    print("- 📊 视频信息API: /api/video/info/{文件路径}")
    print("- 📋 视频列表API: /api/videos")
    
    print("\n🔒 权限控制:")
    print("- 🌐 任何人都可以访问根目录（无需登录）")
    print("- 🔐 未登录用户不能访问 users 目录")
    print("- 👤 管理员 (admin) 可以操作所有文件")
    print("- 👤 普通用户只能操作 users/用户名/ 目录下的文件")
    print("- 📁 创建用户时会自动创建对应的文件夹")
    print("- 🔄 普通用户登录后会自动跳转到自己的文件夹")
    print("\n🔒 安全提示:")
    print("- 请务必在生产环境中修改默认管理员密码")
    print("- 生产环境建议使用 HTTPS")
    print("- ⚠️  文件类型限制已禁用，可以上传任意类型文件")
    print("- 🔐 users 文件夹需要登录后才能访问")
    if PROXY_ENABLED:
        print("- 🔐 代理功能需要登录后才能使用")
        print("- 🔌 WebSocket 代理通过 Socket.IO 实现")
    print("\n")

    if SSL_ENABLED:
        if os.path.exists(SSL_CERT_FILE) and os.path.exists(SSL_KEY_FILE):
            print("使用 HTTPS 协议启动...")
            socketio.run(app, host=host, port=port, 
                        ssl_context=(SSL_CERT_FILE, SSL_KEY_FILE), 
                        debug=False,
                        allow_unsafe_werkzeug=True)
        else:
            print(f"❌ 错误: SSL证书文件不存在!")
            exit(1)
    else:
        print("使用 HTTP 协议启动...")
        socketio.run(app, host=host, port=port, debug=False)