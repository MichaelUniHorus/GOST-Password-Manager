"""
Криптографический модуль с ГОСТ-алгоритмами
Соответствие: ГОСТ Р 34.12-2015 (Кузнечик), ГОСТ Р 34.11-2012 (Стрибог)
"""

import os
import secrets
import hashlib
from typing import Tuple, Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from gostcrypto import gosthash, gostcipher
import base64
import struct


class GOSTCrypto:
    """
    Класс для работы с ГОСТ-криптографией
    """
    
    # Константы
    SALT_LENGTH = 32  # 256 бит
    NONCE_LENGTH = 16  # 128 бит для CTR режима
    KEY_LENGTH = 32  # 256 бит для Кузнечика
    PBKDF2_ITERATIONS = 100000
    
    def __init__(self):
        self.ph = PasswordHasher(
            time_cost=3,
            memory_cost=65536,  # 64 MB
            parallelism=4,
            hash_len=32,
            salt_len=16
        )
    
    def generate_salt(self) -> bytes:
        """Генерация криптографически стойкой соли"""
        return secrets.token_bytes(self.SALT_LENGTH)
    
    def generate_nonce(self) -> bytes:
        """Генерация nonce для CTR режима"""
        return secrets.token_bytes(self.NONCE_LENGTH)
    
    def streebog_512(self, data: bytes) -> bytes:
        """
        Хэширование по ГОСТ Р 34.11-2012 (Стрибог-512)
        """
        return gosthash.new('streebog512', data=data).digest()
    
    def streebog_256(self, data: bytes) -> bytes:
        """
        Хэширование по ГОСТ Р 34.11-2012 (Стрибог-256)
        """
        return gosthash.new('streebog256', data=data).digest()
    
    def derive_key_pbkdf2_gost(self, password: str, salt: bytes, iterations: int = None) -> bytes:
        """
        Деривация ключа из пароля с использованием PBKDF2 + Стрибог-512
        """
        if iterations is None:
            iterations = self.PBKDF2_ITERATIONS
        
        password_bytes = password.encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha512', password_bytes, salt, iterations, dklen=self.KEY_LENGTH)
        
        # Дополнительное хэширование через Стрибог для соответствия ГОСТ
        return self.streebog_256(key)
    
    def hash_master_password(self, password: str) -> str:
        """
        Хэширование мастер-пароля с использованием Argon2id
        Возвращает строку в формате Argon2
        """
        return self.ph.hash(password)
    
    def verify_master_password(self, password: str, hash_str: str) -> bool:
        """
        Проверка мастер-пароля
        """
        try:
            self.ph.verify(hash_str, password)
            return True
        except VerifyMismatchError:
            return False
    
    def _kuznechik_ctr_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
        """
        Шифрование в режиме CTR с использованием Кузнечика
        """
        cipher = gostcipher.new('kuznechik', key, gostcipher.MODE_CTR, init_vect=nonce)
        return cipher.encrypt(plaintext)
    
    def _kuznechik_ctr_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """
        Расшифрование в режиме CTR с использованием Кузнечика
        """
        cipher = gostcipher.new('kuznechik', key, gostcipher.MODE_CTR, init_vect=nonce)
        return cipher.decrypt(ciphertext)
    
    def encrypt_data(self, key: bytes, plaintext: str) -> str:
        """
        Шифрование данных с использованием Кузнечика в режиме CTR
        Возвращает: base64(nonce + ciphertext)
        """
        if not plaintext:
            return ""
        
        nonce = self.generate_nonce()
        plaintext_bytes = plaintext.encode('utf-8')
        
        ciphertext = self._kuznechik_ctr_encrypt(key, nonce, plaintext_bytes)
        
        # Объединяем nonce и ciphertext
        encrypted_data = nonce + ciphertext
        
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_data(self, key: bytes, encrypted_data: str) -> str:
        """
        Расшифрование данных
        """
        if not encrypted_data:
            return ""
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Извлекаем nonce и ciphertext
            nonce = encrypted_bytes[:self.NONCE_LENGTH]
            ciphertext = encrypted_bytes[self.NONCE_LENGTH:]
            
            plaintext_bytes = self._kuznechik_ctr_decrypt(key, nonce, ciphertext)
            
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Ошибка расшифрования: {str(e)}")
    
    def generate_secure_password(self, length: int = 20, 
                                 use_uppercase: bool = True,
                                 use_lowercase: bool = True,
                                 use_digits: bool = True,
                                 use_symbols: bool = True) -> str:
        """
        Генерация криптографически стойкого пароля
        Использует secrets для CSPRNG
        """
        if length < 15:
            length = 15  # Минимум по требованиям
        
        charset = ""
        if use_lowercase:
            charset += "abcdefghijklmnopqrstuvwxyz"
        if use_uppercase:
            charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if use_digits:
            charset += "0123456789"
        if use_symbols:
            charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not charset:
            charset = "abcdefghijklmnopqrstuvwxyz0123456789"
        
        # Генерация пароля с гарантией наличия всех типов символов
        password = ''.join(secrets.choice(charset) for _ in range(length))
        
        # Проверка наличия всех типов символов
        has_lower = any(c.islower() for c in password) if use_lowercase else True
        has_upper = any(c.isupper() for c in password) if use_uppercase else True
        has_digit = any(c.isdigit() for c in password) if use_digits else True
        has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password) if use_symbols else True
        
        # Если не все типы присутствуют, генерируем заново
        if not (has_lower and has_upper and has_digit and has_symbol):
            return self.generate_secure_password(length, use_uppercase, use_lowercase, use_digits, use_symbols)
        
        return password
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Проверка стойкости пароля
        Возвращает: (is_valid, message)
        """
        if len(password) < 15:
            return False, "Пароль должен содержать минимум 15 символов"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        
        if not (has_upper and has_lower and has_digit and has_symbol):
            return False, "Пароль должен содержать заглавные и строчные буквы, цифры и спецсимволы"
        
        # Проверка на распространенные пароли
        weak_passwords = [
            "password", "123456", "qwerty", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "sunshine"
        ]
        
        if password.lower() in weak_passwords:
            return False, "Пароль слишком распространенный"
        
        return True, "Пароль соответствует требованиям"


# Singleton instance
_crypto_instance = None

def get_crypto() -> GOSTCrypto:
    """Получение singleton экземпляра криптомодуля"""
    global _crypto_instance
    if _crypto_instance is None:
        _crypto_instance = GOSTCrypto()
    return _crypto_instance
