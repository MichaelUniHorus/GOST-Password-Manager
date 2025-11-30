"""
Модуль для импорта и экспорта паролей
Поддерживает форматы: CSV, KeePass (.kdbx), собственный формат
"""

import csv
import json
import base64
from datetime import datetime
from typing import List, Dict, Optional
from io import StringIO, BytesIO
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

from crypto_gost import get_crypto


class ImportExportManager:
    """
    Менеджер импорта и экспорта паролей
    """
    
    def __init__(self):
        self.crypto = get_crypto()
    
    # ==================== ИМПОРТ ====================
    
    def import_from_csv(self, csv_content: str, encryption_key: bytes) -> List[Dict]:
        """
        Импорт из CSV
        
        Ожидаемый формат CSV:
        site_name,url,username,password,notes
        
        Args:
            csv_content: Содержимое CSV файла
            encryption_key: Ключ для шифрования импортированных данных
        
        Returns:
            Список словарей с зашифрованными данными
        """
        entries = []
        
        try:
            csv_file = StringIO(csv_content)
            reader = csv.DictReader(csv_file)
            
            for row in reader:
                # Шифруем данные
                entry = {
                    'site_name_enc': self.crypto.encrypt_data(encryption_key, row.get('site_name', '')),
                    'url_enc': self.crypto.encrypt_data(encryption_key, row.get('url', '')),
                    'username_enc': self.crypto.encrypt_data(encryption_key, row.get('username', '')),
                    'password_enc': self.crypto.encrypt_data(encryption_key, row.get('password', '')),
                    'notes_enc': self.crypto.encrypt_data(encryption_key, row.get('notes', '')),
                    'totp_secret_enc': self.crypto.encrypt_data(encryption_key, row.get('totp_secret', '')),
                    'favorite': row.get('favorite', '').lower() == 'true',
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
                
                entries.append(entry)
            
            return entries
            
        except Exception as e:
            raise ValueError(f"Ошибка импорта CSV: {str(e)}")
    
    def import_from_keepass(self, kdbx_content: bytes, kdbx_password: str, encryption_key: bytes) -> List[Dict]:
        """
        Импорт из KeePass (.kdbx)
        
        Args:
            kdbx_content: Содержимое .kdbx файла
            kdbx_password: Пароль от KeePass базы
            encryption_key: Ключ для шифрования импортированных данных
        
        Returns:
            Список словарей с зашифрованными данными
        """
        entries = []
        
        try:
            # Открываем KeePass базу
            kdbx_file = BytesIO(kdbx_content)
            kp = PyKeePass(kdbx_file, password=kdbx_password)
            
            # Получаем все записи
            for entry in kp.entries:
                # Пропускаем записи без пароля
                if not entry.password:
                    continue
                
                # Шифруем данные
                encrypted_entry = {
                    'site_name_enc': self.crypto.encrypt_data(encryption_key, entry.title or ''),
                    'url_enc': self.crypto.encrypt_data(encryption_key, entry.url or ''),
                    'username_enc': self.crypto.encrypt_data(encryption_key, entry.username or ''),
                    'password_enc': self.crypto.encrypt_data(encryption_key, entry.password or ''),
                    'notes_enc': self.crypto.encrypt_data(encryption_key, entry.notes or ''),
                    'totp_secret_enc': '',  # KeePass может хранить TOTP в custom fields
                    'favorite': False,
                    'created_at': entry.ctime or datetime.utcnow(),
                    'updated_at': entry.mtime or datetime.utcnow()
                }
                
                # Проверяем custom fields на TOTP
                if hasattr(entry, 'custom_properties'):
                    for key, value in entry.custom_properties.items():
                        if key.lower() in ['totp', 'otp', 'twofa']:
                            encrypted_entry['totp_secret_enc'] = self.crypto.encrypt_data(encryption_key, value)
                            break
                
                entries.append(encrypted_entry)
            
            return entries
            
        except CredentialsError:
            raise ValueError("Неверный пароль от KeePass базы")
        except Exception as e:
            raise ValueError(f"Ошибка импорта KeePass: {str(e)}")
    
    def import_from_json(self, json_content: str, encryption_key: bytes) -> List[Dict]:
        """
        Импорт из собственного JSON формата (незашифрованного)
        
        Args:
            json_content: JSON содержимое
            encryption_key: Ключ для шифрования
        
        Returns:
            Список словарей с зашифрованными данными
        """
        entries = []
        
        try:
            data = json.loads(json_content)
            
            for item in data:
                entry = {
                    'site_name_enc': self.crypto.encrypt_data(encryption_key, item.get('site_name', '')),
                    'url_enc': self.crypto.encrypt_data(encryption_key, item.get('url', '')),
                    'username_enc': self.crypto.encrypt_data(encryption_key, item.get('username', '')),
                    'password_enc': self.crypto.encrypt_data(encryption_key, item.get('password', '')),
                    'notes_enc': self.crypto.encrypt_data(encryption_key, item.get('notes', '')),
                    'totp_secret_enc': self.crypto.encrypt_data(encryption_key, item.get('totp_secret', '')),
                    'favorite': item.get('favorite', False),
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
                
                entries.append(entry)
            
            return entries
            
        except json.JSONDecodeError:
            raise ValueError("Неверный формат JSON")
        except Exception as e:
            raise ValueError(f"Ошибка импорта JSON: {str(e)}")
    
    # ==================== ЭКСПОРТ ====================
    
    def export_to_csv(self, entries: List[Dict], encryption_key: bytes) -> str:
        """
        Экспорт в CSV
        
        Args:
            entries: Список записей (зашифрованных)
            encryption_key: Ключ для расшифровки
        
        Returns:
            CSV строка
        """
        output = StringIO()
        fieldnames = ['site_name', 'url', 'username', 'password', 'notes', 'totp_secret', 'favorite']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        
        writer.writeheader()
        
        for entry in entries:
            try:
                row = {
                    'site_name': self.crypto.decrypt_data(encryption_key, entry.get('site_name_enc', '')),
                    'url': self.crypto.decrypt_data(encryption_key, entry.get('url_enc', '')),
                    'username': self.crypto.decrypt_data(encryption_key, entry.get('username_enc', '')),
                    'password': self.crypto.decrypt_data(encryption_key, entry.get('password_enc', '')),
                    'notes': self.crypto.decrypt_data(encryption_key, entry.get('notes_enc', '')),
                    'totp_secret': self.crypto.decrypt_data(encryption_key, entry.get('totp_secret_enc', '')),
                    'favorite': entry.get('favorite', False)
                }
                writer.writerow(row)
            except Exception as e:
                print(f"Ошибка экспорта записи: {e}")
                continue
        
        return output.getvalue()
    
    def export_to_json(self, entries: List[Dict], encryption_key: bytes, include_metadata: bool = True) -> str:
        """
        Экспорт в JSON
        
        Args:
            entries: Список записей (зашифрованных)
            encryption_key: Ключ для расшифровки
            include_metadata: Включать ли метаданные (даты, favorite)
        
        Returns:
            JSON строка
        """
        export_data = []
        
        for entry in entries:
            try:
                item = {
                    'site_name': self.crypto.decrypt_data(encryption_key, entry.get('site_name_enc', '')),
                    'url': self.crypto.decrypt_data(encryption_key, entry.get('url_enc', '')),
                    'username': self.crypto.decrypt_data(encryption_key, entry.get('username_enc', '')),
                    'password': self.crypto.decrypt_data(encryption_key, entry.get('password_enc', '')),
                    'notes': self.crypto.decrypt_data(encryption_key, entry.get('notes_enc', '')),
                    'totp_secret': self.crypto.decrypt_data(encryption_key, entry.get('totp_secret_enc', ''))
                }
                
                if include_metadata:
                    item['favorite'] = entry.get('favorite', False)
                    item['created_at'] = entry.get('created_at').isoformat() if entry.get('created_at') else None
                    item['updated_at'] = entry.get('updated_at').isoformat() if entry.get('updated_at') else None
                
                export_data.append(item)
            except Exception as e:
                print(f"Ошибка экспорта записи: {e}")
                continue
        
        return json.dumps(export_data, indent=2, ensure_ascii=False)
    
    def export_to_encrypted_json(self, entries: List[Dict], export_password: str) -> str:
        """
        Экспорт в зашифрованный JSON (собственный формат .gostvault)
        
        Args:
            entries: Список записей (уже зашифрованных в БД)
            export_password: Пароль для экспорта
        
        Returns:
            JSON строка с зашифрованными данными
        """
        # Генерируем соль для экспорта
        export_salt = self.crypto.generate_salt()
        
        # Деривируем ключ из пароля экспорта
        export_key = self.crypto.derive_key_pbkdf2_gost(export_password, export_salt)
        
        # Подготавливаем данные для экспорта
        export_data = {
            'version': '1.0',
            'format': 'gostvault',
            'created_at': datetime.utcnow().isoformat(),
            'salt': base64.b64encode(export_salt).decode('utf-8'),
            'entries': []
        }
        
        # Экспортируем записи (они уже зашифрованы, просто копируем)
        for entry in entries:
            export_entry = {
                'site_name_enc': entry.get('site_name_enc', ''),
                'url_enc': entry.get('url_enc', ''),
                'username_enc': entry.get('username_enc', ''),
                'password_enc': entry.get('password_enc', ''),
                'notes_enc': entry.get('notes_enc', ''),
                'totp_secret_enc': entry.get('totp_secret_enc', ''),
                'favorite': entry.get('favorite', False),
                'created_at': entry.get('created_at').isoformat() if entry.get('created_at') else None
            }
            export_data['entries'].append(export_entry)
        
        # Шифруем весь JSON
        json_str = json.dumps(export_data, ensure_ascii=False)
        encrypted_json = self.crypto.encrypt_data(export_key, json_str)
        
        # Возвращаем в формате: salt + encrypted_data
        result = {
            'version': '1.0',
            'format': 'gostvault',
            'salt': base64.b64encode(export_salt).decode('utf-8'),
            'data': encrypted_json
        }
        
        return json.dumps(result, indent=2)


# Singleton instance
_manager_instance = None

def get_import_export_manager() -> ImportExportManager:
    """Получение singleton экземпляра менеджера"""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = ImportExportManager()
    return _manager_instance
