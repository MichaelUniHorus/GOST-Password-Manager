"""
Модели базы данных для менеджера паролей
"""

from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

Base = declarative_base()


class MasterPassword(Base):
    """
    Таблица для хранения мастер-пароля (хэш)
    """
    __tablename__ = 'master_password'
    
    id = Column(Integer, primary_key=True)
    password_hash = Column(String(255), nullable=False)
    salt = Column(String(255), nullable=False)  # Base64 encoded
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<MasterPassword(id={self.id})>"


class MasterEncryptionKey(Base):
    """
    Таблица для хранения главного ключа шифрования (MEK)
    MEK шифрует все данные, сам MEK зашифрован ключом из мастер-пароля
    Это позволяет менять мастер-пароль без перешифровки всех записей
    """
    __tablename__ = 'master_encryption_key'
    
    id = Column(Integer, primary_key=True)
    encrypted_key = Column(String(512), nullable=False)  # Base64 encoded зашифрованный MEK
    kdf_salt = Column(String(255), nullable=False)  # Соль для KDF
    kdf_iterations = Column(Integer, nullable=False, default=100000)  # Итерации PBKDF2
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<MasterEncryptionKey(id={self.id})>"


class PasswordEntry(Base):
    """
    Таблица для хранения записей паролей
    Все чувствительные данные хранятся в зашифрованном виде
    """
    __tablename__ = 'password_entries'
    
    id = Column(Integer, primary_key=True)
    site_name_enc = Column(Text, nullable=False)  # Зашифрованное название сайта
    url_enc = Column(Text)  # Зашифрованный URL
    username_enc = Column(Text, nullable=False)  # Зашифрованный логин
    password_enc = Column(Text, nullable=False)  # Зашифрованный пароль
    notes_enc = Column(Text)  # Зашифрованные заметки
    totp_secret_enc = Column(Text)  # Зашифрованный TOTP секрет
    custom_fields_enc = Column(Text)  # Зашифрованные кастомные поля (JSON)
    
    # Метаданные (не шифруются)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_accessed = Column(DateTime)
    favorite = Column(Boolean, default=False)
    
    def __repr__(self):
        return f"<PasswordEntry(id={self.id})>"


class AuditLog(Base):
    """
    Таблица для аудита действий
    Хранит только метаданные, без секретов
    """
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    action = Column(String(50), nullable=False)  # create, read, update, delete, login, etc.
    entry_id = Column(Integer)  # ID записи (если применимо)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45))  # IPv4 или IPv6
    user_agent = Column(String(255))
    success = Column(Boolean, default=True)
    details = Column(Text)  # Дополнительная информация (без секретов)
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, action={self.action})>"


class LoginAttempt(Base):
    """
    Таблица для отслеживания попыток входа
    Защита от brute-force атак
    """
    __tablename__ = 'login_attempts'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=False)
    
    def __repr__(self):
        return f"<LoginAttempt(id={self.id}, ip={self.ip_address}, success={self.success})>"


class SessionToken(Base):
    """
    Таблица для хранения сессионных токенов
    """
    __tablename__ = 'session_tokens'
    
    id = Column(Integer, primary_key=True)
    token = Column(String(255), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45))
    user_agent = Column(String(255))
    
    def __repr__(self):
        return f"<SessionToken(id={self.id}, expires={self.expires_at})>"


class BackupSettings(Base):
    """
    Таблица для настроек автоматического резервного копирования
    """
    __tablename__ = 'backup_settings'
    
    id = Column(Integer, primary_key=True)
    enabled = Column(Boolean, default=False)
    frequency = Column(String(20), default='daily')  # daily, weekly, monthly
    keep_count = Column(Integer, default=10)  # Количество копий для хранения
    last_backup = Column(DateTime)
    backup_path = Column(String(512), default='backups')
    
    def __repr__(self):
        return f"<BackupSettings(enabled={self.enabled}, frequency={self.frequency})>"


class Database:
    """
    Класс для управления базой данных
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.getenv('DATABASE_PATH', 'password_manager.db')
        
        self.db_path = db_path
        self.engine = create_engine(f'sqlite:///{db_path}', echo=False)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
    
    def get_session(self):
        """Получение новой сессии БД"""
        return self.Session()
    
    def init_db(self):
        """Инициализация базы данных"""
        Base.metadata.create_all(self.engine)
    
    def drop_all(self):
        """Удаление всех таблиц (для тестирования)"""
        Base.metadata.drop_all(self.engine)
    
    def backup_db(self, backup_path: str):
        """Создание резервной копии БД"""
        import shutil
        if os.path.exists(self.db_path):
            shutil.copy2(self.db_path, backup_path)
            return True
        return False


# Singleton instance
_db_instance = None

def get_database(db_path: str = None) -> Database:
    """Получение singleton экземпляра БД"""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(db_path)
    return _db_instance
