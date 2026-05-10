from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import hashlib
import jwt
import uuid
import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'XiGuangBaoZhuang2026!@#'
CORS(app)

def get_db():
    conn = sqlite3.connect('database.sqlite')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            phone TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            nickname TEXT,
            username TEXT,
            role TEXT DEFAULT 'user',
            isAdmin INTEGER DEFAULT 0,
            createdAt TEXT,
            lastLogin TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            userId TEXT PRIMARY KEY,
            calculateCount INTEGER DEFAULT 0,
            copyCount INTEGER DEFAULT 0,
            onlineMinutes REAL DEFAULT 0,
            lastActiveAt TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS announcements (
            id TEXT PRIMARY KEY,
            title TEXT,
            content TEXT,
            isImportant INTEGER DEFAULT 0,
            createdAt TEXT
        )
    ''')
    
    create_default_admins(cursor, conn)
    conn.close()

def create_default_admins(cursor, conn):
    cursor.execute('SELECT * FROM users WHERE phone = ?', ('13800000000',))
    if not cursor.fetchone():
        hashed_pwd = hashlib.sha256(b'123456').hexdigest()
        cursor.execute('''
            INSERT INTO users (id, phone, password, name, nickname, username, role, isAdmin, createdAt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('admin_001', '13800000000', hashed_pwd, '超级管理员', '超级管理员', '13800000000', 'admin', 1, datetime.datetime.now().isoformat()))
        print('✅ 默认管理员创建成功: 13800000000 / 123456')
    
    cursor.execute('SELECT * FROM users WHERE phone = ?', ('13277205591',))
    if not cursor.fetchone():
        hashed_pwd = hashlib.sha256(b'hdkdd520').hexdigest()
        cursor.execute('''
            INSERT INTO users (id, phone, password, name, nickname, username, role, isAdmin, createdAt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('admin_002', '13277205591', hashed_pwd, '黄何', '黄何', '13277205591', 'admin', 1, datetime.datetime.now().isoformat()))
        print('✅ 管理员黄何创建成功: 13277205591 / hdkdd520')
    
    conn.commit()

def generate_token(user_id):
    payload = {
        'userId': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['userId']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    phone = data.get('phone')
    password = data.get('password')
    
    if not phone or not password:
        return jsonify({'error': '缺少参数'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE phone = ?', (phone,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': '手机号或密码错误'}), 401
    
    hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
    if user['password'] != hashed_pwd:
        return jsonify({'error': '手机号或密码错误'}), 401
    
    token = generate_token(user['id'])
    
    conn = get_db()
    conn.execute('UPDATE users SET lastLogin = ? WHERE id = ?', (datetime.datetime.now().isoformat(), user['id']))
    conn.commit()
    conn.close()
    
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'phone': user['phone'],
            'name': user['name'],
            'nickname': user['nickname'],
            'username': user['username'],
            'role': user['role'],
            'isAdmin': bool(user['isAdmin']),
            'createdAt': user['createdAt']
        }
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    phone = data.get('phone')
    password = data.get('password')
    name = data.get('name')
    
    if not phone or not password or not name:
        return jsonify({'error': '缺少参数'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE phone = ?', (phone,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': '该手机号已被注册'}), 400
    
    user_id = 'user_' + str(datetime.datetime.now().timestamp())
    hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
    
    cursor.execute('''
        INSERT INTO users (id, phone, password, name, nickname, username, role, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, phone, hashed_pwd, name, name, phone, 'user', datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    token = generate_token(user_id)
    
    return jsonify({
        'token': token,
        'user': {
            'id': user_id,
            'phone': phone,
            'name': name,
            'nickname': name,
            'username': phone,
            'role': 'user',
            'isAdmin': False,
            'createdAt': datetime.datetime.now().isoformat()
        }
    })

@app.route('/api/auth/me', methods=['GET'])
def get_me():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': '未授权'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({'error': '无效token'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    return jsonify({
        'user': {
            'id': user['id'],
            'phone': user['phone'],
            'name': user['name'],
            'nickname': user['nickname'],
            'username': user['username'],
            'role': user['role'],
            'isAdmin': bool(user['isAdmin']),
            'createdAt': user['createdAt']
        }
    })

@app.route('/api/auth/me', methods=['PUT'])
def update_me():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': '未授权'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({'error': '无效token'}), 401
    
    data = request.get_json()
    name = data.get('name')
    nickname = data.get('nickname')
    password = data.get('password')
    
    conn = get_db()
    updates = []
    params = []
    
    if name:
        updates.append('name = ?')
        params.append(name)
    if nickname:
        updates.append('nickname = ?')
        params.append(nickname)
    if password:
        updates.append('password = ?')
        params.append(hashlib.sha256(password.encode()).hexdigest())
    
    params.append(user_id)
    
    if updates:
        conn.execute(f'UPDATE users SET {", ".join(updates)} WHERE id = ?', params)
        conn.commit()
    
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    return jsonify({
        'user': {
            'id': user['id'],
            'phone': user['phone'],
            'name': user['name'],
            'nickname': user['nickname'],
            'username': user['username'],
            'role': user['role'],
            'isAdmin': bool(user['isAdmin']),
            'createdAt': user['createdAt']
        }
    })

@app.route('/api/auth/users', methods=['GET'])
def get_users():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': '未授权'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({'error': '无效token'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    
    result = []
    for user in users:
        result.append({
            'id': user['id'],
            'phone': user['phone'],
            'name': user['name'],
            'nickname': user['nickname'],
            'username': user['username'],
            'role': user['role'],
            'isAdmin': bool(user['isAdmin']),
            'createdAt': user['createdAt'],
            'lastLogin': user['lastLogin'],
            'stats': {'calculateCount': 0, 'copyCount': 0, 'onlineDuration': 0}
        })
    
    return jsonify({'users': result})

@app.route('/api/auth/users', methods=['POST'])
def add_user():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': '未授权'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({'error': '无效token'}), 401
    
    data = request.get_json()
    phone = data.get('phone')
    password = data.get('password')
    name = data.get('name')
    
    if not phone or not password or not name:
        return jsonify({'error': '缺少参数'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE phone = ?', (phone,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': '该手机号已存在'}), 400
    
    user_id = 'user_' + str(datetime.datetime.now().timestamp())
    hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
    
    cursor.execute('''
        INSERT INTO users (id, phone, password, name, nickname, username, role, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, phone, hashed_pwd, name, name, phone, 'user', datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True}), 201

@app.route('/api/auth/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': '未授权'}), 401
    
    token = auth_header.split(' ')[1]
    verify_token(token)
    
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/auth/stats/<user_id>/<stat_type>', methods=['POST'])
def update_stats(user_id, stat_type):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': '未授权'}), 401
    
    token = auth_header.split(' ')[1]
    verify_token(token)
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM stats WHERE userId = ?', (user_id,))
    stat = cursor.fetchone()
    
    if not stat:
        calc_count = 1 if stat_type == 'calculate' else 0
        copy_count = 1 if stat_type == 'copy' else 0
        cursor.execute('''
            INSERT INTO stats (userId, calculateCount, copyCount, onlineMinutes, lastActiveAt)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, calc_count, copy_count, 0, datetime.datetime.now().isoformat()))
    else:
        if stat_type == 'calculate':
            cursor.execute('UPDATE stats SET calculateCount = calculateCount + 1, lastActiveAt = ? WHERE userId = ?', 
                         (datetime.datetime.now().isoformat(), user_id))
        elif stat_type == 'copy':
            cursor.execute('UPDATE stats SET copyCount = copyCount + 1, lastActiveAt = ? WHERE userId = ?', 
                         (datetime.datetime.now().isoformat(), user_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/auth/reset-password/<user_id>', methods=['POST'])
def reset_password(user_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': '未授权'}), 401
    
    token = auth_header.split(' ')[1]
    verify_token(token)
    
    data = request.get_json()
    new_password = data.get('newPassword')
    
    if not new_password:
        return jsonify({'error': '缺少参数'}), 400
    
    hashed_pwd = hashlib.sha256(new_password.encode()).hexdigest()
    
    conn = get_db()
    conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_pwd, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/', methods=['GET'])
def index():
    try:
        # 先尝试根目录
        base_dir = os.path.dirname(__file__)
        if os.path.exists(os.path.join(base_dir, 'index.html')):
            return send_from_directory(base_dir, 'index.html')
        # 再尝试 public 目录
        public_dir = os.path.join(base_dir, 'public')
        if os.path.exists(os.path.join(public_dir, 'index.html')):
            return send_from_directory(public_dir, 'index.html')
    except Exception as e:
        print(f"Error serving index: {e}")
    return '曦光包装袋报价器后端服务运行中...'

@app.route('/<path:path>', methods=['GET'])
def serve_static(path):
    try:
        base_dir = os.path.dirname(__file__)
        public_dir = os.path.join(base_dir, 'public')
        
        # 先尝试根目录
        if os.path.exists(os.path.join(base_dir, path)):
            return send_from_directory(base_dir, path)
        # 再尝试 public 目录
        if os.path.exists(os.path.join(public_dir, path)):
            return send_from_directory(public_dir, path)
    except Exception as e:
        print(f"Error serving static file {path}: {e}")
    return 'File not found', 404

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=3001, debug=False)
