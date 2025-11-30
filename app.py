"""
Flask приложение - менеджер паролей с ГОСТ-криптографией
"""

import os
import secrets
import base64
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
import pyotp
import qrcode
from io import BytesIO

from models import (
    get_database, MasterPassword, PasswordEntry, 
    AuditLog, LoginAttempt, SessionToken
)
from crypto_gost import get_crypto

# Загрузка переменных окружения
load_dotenv()

app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Только для HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.getenv('SESSION_TIMEOUT', 300)))

CORS(app, supports_credentials=True)

# Инициализация
db = get_database()
crypto = get_crypto()

# Константы безопасности
MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
LOCKOUT_DURATION = int(os.getenv('LOCKOUT_DURATION', 30))  # секунды


def log_audit(action: str, entry_id: int = None, success: bool = True, details: str = None):
    """Логирование действий в аудит"""
    try:
        db_session = db.get_session()
        log = AuditLog(
            action=action,
            entry_id=entry_id,
            success=success,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:255],
            details=details
        )
        db_session.add(log)
        db_session.commit()
        db_session.close()
    except Exception as e:
        print(f"Ошибка логирования: {e}")


def check_rate_limit(ip_address: str) -> tuple[bool, int]:
    """
    Проверка ограничения попыток входа
    Возвращает: (allowed, remaining_attempts)
    """
    db_session = db.get_session()
    
    # Получаем попытки за последние LOCKOUT_DURATION секунд
    cutoff_time = datetime.utcnow() - timedelta(seconds=LOCKOUT_DURATION)
    recent_attempts = db_session.query(LoginAttempt).filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.timestamp > cutoff_time,
        LoginAttempt.success == False
    ).count()
    
    db_session.close()
    
    remaining = MAX_LOGIN_ATTEMPTS - recent_attempts
    return remaining > 0, remaining


def record_login_attempt(ip_address: str, success: bool):
    """Запись попытки входа"""
    db_session = db.get_session()
    attempt = LoginAttempt(
        ip_address=ip_address,
        success=success
    )
    db_session.add(attempt)
    db_session.commit()
    db_session.close()


def require_auth(f):
    """Декоратор для проверки авторизации"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            return jsonify({'error': 'Требуется авторизация'}), 401
        
        # Проверка времени последней активности (auto-lock)
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.utcnow() - last_activity > timedelta(minutes=5):
                session.clear()
                return jsonify({'error': 'Сессия истекла'}), 401
        
        session['last_activity'] = datetime.utcnow().isoformat()
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """Главная страница"""
    return send_from_directory('static', 'index.html')


@app.route('/api/init', methods=['GET'])
def check_init():
    """Проверка инициализации мастер-пароля"""
    db_session = db.get_session()
    master = db_session.query(MasterPassword).first()
    db_session.close()
    
    return jsonify({
        'initialized': master is not None
    })


@app.route('/api/init', methods=['POST'])
def initialize():
    """Инициализация мастер-пароля"""
    data = request.get_json()
    master_password = data.get('master_password')
    
    if not master_password:
        return jsonify({'error': 'Мастер-пароль не указан'}), 400
    
    # Проверка стойкости пароля
    is_valid, message = crypto.validate_password_strength(master_password)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    db_session = db.get_session()
    
    # Проверка, что мастер-пароль еще не установлен
    existing = db_session.query(MasterPassword).first()
    if existing:
        db_session.close()
        return jsonify({'error': 'Мастер-пароль уже установлен'}), 400
    
    # Генерация соли и хэширование
    salt = crypto.generate_salt()
    password_hash = crypto.hash_master_password(master_password)
    
    master = MasterPassword(
        password_hash=password_hash,
        salt=base64.b64encode(salt).decode('utf-8')
    )
    
    db_session.add(master)
    db_session.commit()
    db_session.close()
    
    log_audit('init_master_password', success=True)
    
    return jsonify({'success': True, 'message': 'Мастер-пароль установлен'})


@app.route('/api/login', methods=['POST'])
def login():
    """Вход с мастер-паролем"""
    data = request.get_json()
    master_password = data.get('master_password')
    
    if not master_password:
        return jsonify({'error': 'Мастер-пароль не указан'}), 400
    
    ip_address = request.remote_addr
    
    # Проверка rate limit
    allowed, remaining = check_rate_limit(ip_address)
    if not allowed:
        log_audit('login', success=False, details='Rate limit exceeded')
        return jsonify({
            'error': f'Слишком много неудачных попыток. Попробуйте через {LOCKOUT_DURATION} секунд'
        }), 429
    
    db_session = db.get_session()
    master = db_session.query(MasterPassword).first()
    
    if not master:
        db_session.close()
        return jsonify({'error': 'Мастер-пароль не установлен'}), 400
    
    # Проверка пароля
    if crypto.verify_master_password(master_password, master.password_hash):
        # Успешный вход
        record_login_attempt(ip_address, True)
        
        # Деривация ключа шифрования из мастер-пароля
        salt = base64.b64decode(master.salt)
        encryption_key = crypto.derive_key_pbkdf2_gost(master_password, salt)
        
        # Сохранение в сессии
        session['authenticated'] = True
        session['encryption_key'] = base64.b64encode(encryption_key).decode('utf-8')
        session['last_activity'] = datetime.utcnow().isoformat()
        session.permanent = True
        
        db_session.close()
        log_audit('login', success=True)
        
        return jsonify({'success': True, 'message': 'Вход выполнен'})
    else:
        # Неудачная попытка
        record_login_attempt(ip_address, False)
        db_session.close()
        log_audit('login', success=False)
        
        return jsonify({
            'error': f'Неверный мастер-пароль. Осталось попыток: {remaining - 1}'
        }), 401


@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    """Выход из системы"""
    log_audit('logout', success=True)
    session.clear()
    return jsonify({'success': True, 'message': 'Выход выполнен'})


@app.route('/api/entries', methods=['GET'])
@require_auth
def get_entries():
    """Получение всех записей паролей"""
    db_session = db.get_session()
    entries = db_session.query(PasswordEntry).all()
    
    encryption_key = base64.b64decode(session['encryption_key'])
    
    result = []
    for entry in entries:
        try:
            decrypted_entry = {
                'id': entry.id,
                'site_name': crypto.decrypt_data(encryption_key, entry.site_name_enc),
                'url': crypto.decrypt_data(encryption_key, entry.url_enc) if entry.url_enc else '',
                'username': crypto.decrypt_data(encryption_key, entry.username_enc),
                'password': crypto.decrypt_data(encryption_key, entry.password_enc),
                'notes': crypto.decrypt_data(encryption_key, entry.notes_enc) if entry.notes_enc else '',
                'has_totp': bool(entry.totp_secret_enc),
                'favorite': entry.favorite,
                'created_at': entry.created_at.isoformat(),
                'updated_at': entry.updated_at.isoformat()
            }
            result.append(decrypted_entry)
        except Exception as e:
            print(f"Ошибка расшифрования записи {entry.id}: {e}")
    
    db_session.close()
    log_audit('list_entries', success=True)
    
    return jsonify({'entries': result})


@app.route('/api/entries', methods=['POST'])
@require_auth
def create_entry():
    """Создание новой записи пароля"""
    data = request.get_json()
    
    required_fields = ['site_name', 'username', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Поле {field} обязательно'}), 400
    
    encryption_key = base64.b64decode(session['encryption_key'])
    
    db_session = db.get_session()
    
    entry = PasswordEntry(
        site_name_enc=crypto.encrypt_data(encryption_key, data['site_name']),
        url_enc=crypto.encrypt_data(encryption_key, data.get('url', '')),
        username_enc=crypto.encrypt_data(encryption_key, data['username']),
        password_enc=crypto.encrypt_data(encryption_key, data['password']),
        notes_enc=crypto.encrypt_data(encryption_key, data.get('notes', '')),
        totp_secret_enc=crypto.encrypt_data(encryption_key, data.get('totp_secret', '')) if data.get('totp_secret') else None,
        favorite=data.get('favorite', False)
    )
    
    db_session.add(entry)
    db_session.commit()
    entry_id = entry.id
    db_session.close()
    
    log_audit('create_entry', entry_id=entry_id, success=True)
    
    return jsonify({'success': True, 'id': entry_id, 'message': 'Запись создана'})


@app.route('/api/entries/<int:entry_id>', methods=['PUT'])
@require_auth
def update_entry(entry_id):
    """Обновление записи пароля"""
    data = request.get_json()
    
    encryption_key = base64.b64decode(session['encryption_key'])
    
    db_session = db.get_session()
    entry = db_session.query(PasswordEntry).filter_by(id=entry_id).first()
    
    if not entry:
        db_session.close()
        return jsonify({'error': 'Запись не найдена'}), 404
    
    # Обновление полей
    if 'site_name' in data:
        entry.site_name_enc = crypto.encrypt_data(encryption_key, data['site_name'])
    if 'url' in data:
        entry.url_enc = crypto.encrypt_data(encryption_key, data['url'])
    if 'username' in data:
        entry.username_enc = crypto.encrypt_data(encryption_key, data['username'])
    if 'password' in data:
        entry.password_enc = crypto.encrypt_data(encryption_key, data['password'])
    if 'notes' in data:
        entry.notes_enc = crypto.encrypt_data(encryption_key, data['notes'])
    if 'totp_secret' in data:
        entry.totp_secret_enc = crypto.encrypt_data(encryption_key, data['totp_secret']) if data['totp_secret'] else None
    if 'favorite' in data:
        entry.favorite = data['favorite']
    
    entry.updated_at = datetime.utcnow()
    
    db_session.commit()
    db_session.close()
    
    log_audit('update_entry', entry_id=entry_id, success=True)
    
    return jsonify({'success': True, 'message': 'Запись обновлена'})


@app.route('/api/entries/<int:entry_id>', methods=['DELETE'])
@require_auth
def delete_entry(entry_id):
    """Удаление записи пароля"""
    db_session = db.get_session()
    entry = db_session.query(PasswordEntry).filter_by(id=entry_id).first()
    
    if not entry:
        db_session.close()
        return jsonify({'error': 'Запись не найдена'}), 404
    
    db_session.delete(entry)
    db_session.commit()
    db_session.close()
    
    log_audit('delete_entry', entry_id=entry_id, success=True)
    
    return jsonify({'success': True, 'message': 'Запись удалена'})


@app.route('/api/generate-password', methods=['POST'])
@require_auth
def generate_password():
    """Генерация безопасного пароля"""
    data = request.get_json() or {}
    
    length = data.get('length', 20)
    use_uppercase = data.get('use_uppercase', True)
    use_lowercase = data.get('use_lowercase', True)
    use_digits = data.get('use_digits', True)
    use_symbols = data.get('use_symbols', True)
    
    password = crypto.generate_secure_password(
        length=length,
        use_uppercase=use_uppercase,
        use_lowercase=use_lowercase,
        use_digits=use_digits,
        use_symbols=use_symbols
    )
    
    return jsonify({'password': password})


@app.route('/api/totp/<int:entry_id>', methods=['GET'])
@require_auth
def get_totp(entry_id):
    """Получение TOTP кода для записи"""
    db_session = db.get_session()
    entry = db_session.query(PasswordEntry).filter_by(id=entry_id).first()
    
    if not entry or not entry.totp_secret_enc:
        db_session.close()
        return jsonify({'error': 'TOTP не настроен для этой записи'}), 404
    
    encryption_key = base64.b64decode(session['encryption_key'])
    
    try:
        totp_secret = crypto.decrypt_data(encryption_key, entry.totp_secret_enc)
        totp = pyotp.TOTP(totp_secret)
        code = totp.now()
        remaining = 30 - (datetime.utcnow().second % 30)
        
        db_session.close()
        
        return jsonify({
            'code': code,
            'remaining_seconds': remaining
        })
    except Exception as e:
        db_session.close()
        return jsonify({'error': f'Ошибка генерации TOTP: {str(e)}'}), 500


@app.route('/api/audit-logs', methods=['GET'])
@require_auth
def get_audit_logs():
    """Получение логов аудита"""
    db_session = db.get_session()
    
    limit = request.args.get('limit', 100, type=int)
    logs = db_session.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    result = []
    for log in logs:
        result.append({
            'id': log.id,
            'action': log.action,
            'entry_id': log.entry_id,
            'timestamp': log.timestamp.isoformat(),
            'ip_address': log.ip_address,
            'success': log.success,
            'details': log.details
        })
    
    db_session.close()
    
    return jsonify({'logs': result})


if __name__ == '__main__':
    # Инициализация БД
    db.init_db()
    
    # Запуск в режиме разработки
    # В продакшене использовать gunicorn или waitress
    app.run(host='127.0.0.1', port=5000, debug=True, ssl_context='adhoc')
