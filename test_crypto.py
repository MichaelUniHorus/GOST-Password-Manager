"""
Unit-тесты для криптографического модуля
"""

import pytest
from crypto_gost import GOSTCrypto


class TestGOSTCrypto:
    """Тесты для класса GOSTCrypto"""
    
    def setup_method(self):
        """Инициализация перед каждым тестом"""
        self.crypto = GOSTCrypto()
    
    def test_generate_salt(self):
        """Тест генерации соли"""
        salt1 = self.crypto.generate_salt()
        salt2 = self.crypto.generate_salt()
        
        assert len(salt1) == 32
        assert len(salt2) == 32
        assert salt1 != salt2  # Соли должны быть разными
    
    def test_generate_nonce(self):
        """Тест генерации nonce"""
        nonce1 = self.crypto.generate_nonce()
        nonce2 = self.crypto.generate_nonce()
        
        assert len(nonce1) == 8  # 64 бит для CTR режима
        assert len(nonce2) == 8
        assert nonce1 != nonce2
    
    def test_streebog_512(self):
        """Тест хэширования Стрибог-512"""
        data = b"test data"
        hash1 = self.crypto.streebog_512(data)
        hash2 = self.crypto.streebog_512(data)
        
        assert len(hash1) == 64  # 512 бит = 64 байта
        assert hash1 == hash2  # Одинаковые данные -> одинаковый хэш
        
        # Разные данные -> разные хэши
        hash3 = self.crypto.streebog_512(b"different data")
        assert hash1 != hash3
    
    def test_streebog_256(self):
        """Тест хэширования Стрибог-256"""
        data = b"test data"
        hash1 = self.crypto.streebog_256(data)
        
        assert len(hash1) == 32  # 256 бит = 32 байта
    
    def test_derive_key_pbkdf2_gost(self):
        """Тест деривации ключа"""
        password = "test_password"
        salt = self.crypto.generate_salt()
        
        key1 = self.crypto.derive_key_pbkdf2_gost(password, salt)
        key2 = self.crypto.derive_key_pbkdf2_gost(password, salt)
        
        assert len(key1) == 32  # 256 бит
        assert key1 == key2  # Одинаковые пароль и соль -> одинаковый ключ
        
        # Другая соль -> другой ключ
        salt2 = self.crypto.generate_salt()
        key3 = self.crypto.derive_key_pbkdf2_gost(password, salt2)
        assert key1 != key3
    
    def test_hash_master_password(self):
        """Тест хэширования мастер-пароля"""
        password = "MySecurePassword123!"
        hash1 = self.crypto.hash_master_password(password)
        
        assert isinstance(hash1, str)
        assert len(hash1) > 50  # Argon2 хэш довольно длинный
    
    def test_verify_master_password(self):
        """Тест проверки мастер-пароля"""
        password = "MySecurePassword123!"
        hash_str = self.crypto.hash_master_password(password)
        
        # Правильный пароль
        assert self.crypto.verify_master_password(password, hash_str) is True
        
        # Неправильный пароль
        assert self.crypto.verify_master_password("wrong_password", hash_str) is False
    
    def test_encrypt_decrypt_data(self):
        """Тест шифрования и расшифрования данных"""
        key = self.crypto.generate_salt()  # Используем как ключ
        plaintext = "Секретные данные 🔐"
        
        # Шифрование
        encrypted = self.crypto.encrypt_data(key, plaintext)
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0
        assert encrypted != plaintext
        
        # Расшифрование
        decrypted = self.crypto.decrypt_data(key, encrypted)
        assert decrypted == plaintext
    
    def test_encrypt_empty_string(self):
        """Тест шифрования пустой строки"""
        key = self.crypto.generate_salt()
        encrypted = self.crypto.encrypt_data(key, "")
        assert encrypted == ""
        
        decrypted = self.crypto.decrypt_data(key, "")
        assert decrypted == ""
    
    def test_decrypt_with_wrong_key(self):
        """Тест расшифрования с неправильным ключом"""
        key1 = self.crypto.generate_salt()
        key2 = self.crypto.generate_salt()
        plaintext = "Secret data"
        
        encrypted = self.crypto.encrypt_data(key1, plaintext)
        
        # Расшифрование с другим ключом должно дать мусор
        with pytest.raises(Exception):
            self.crypto.decrypt_data(key2, encrypted)
    
    def test_generate_secure_password(self):
        """Тест генерации безопасного пароля"""
        password = self.crypto.generate_secure_password(20)
        
        assert len(password) == 20
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(not c.isalnum() for c in password)
    
    def test_generate_password_min_length(self):
        """Тест минимальной длины пароля"""
        password = self.crypto.generate_secure_password(10)  # Меньше 15
        assert len(password) == 15  # Должно быть увеличено до 15
    
    def test_validate_password_strength(self):
        """Тест проверки стойкости пароля"""
        # Слабый пароль (короткий)
        valid, msg = self.crypto.validate_password_strength("short")
        assert valid is False
        assert "15 символов" in msg
        
        # Слабый пароль (нет разнообразия)
        valid, msg = self.crypto.validate_password_strength("aaaaaaaaaaaaaaaaa")
        assert valid is False
        
        # Сильный пароль
        valid, msg = self.crypto.validate_password_strength("MyS3cur3P@ssw0rd!2025")
        assert valid is True
        assert "соответствует требованиям" in msg
    
    def test_generate_mek(self):
        """Тест генерации MEK"""
        mek1 = self.crypto.generate_mek()
        mek2 = self.crypto.generate_mek()
        
        assert len(mek1) == 32
        assert len(mek2) == 32
        assert mek1 != mek2
    
    def test_encrypt_decrypt_mek(self):
        """Тест шифрования и расшифрования MEK"""
        mek = self.crypto.generate_mek()
        master_password = "MyMasterPassword123!"
        salt = self.crypto.generate_salt()
        
        # Шифрование MEK
        encrypted_mek = self.crypto.encrypt_mek(mek, master_password, salt)
        assert len(encrypted_mek) > len(mek)  # Должен включать nonce
        
        # Расшифрование MEK
        decrypted_mek = self.crypto.decrypt_mek(encrypted_mek, master_password, salt)
        assert decrypted_mek == mek
    
    def test_mek_with_wrong_password(self):
        """Тест расшифрования MEK с неправильным паролем"""
        mek = self.crypto.generate_mek()
        password1 = "CorrectPassword123!"
        password2 = "WrongPassword456!"
        salt = self.crypto.generate_salt()
        
        encrypted_mek = self.crypto.encrypt_mek(mek, password1, salt)
        
        # Расшифрование с другим паролем даст неправильный MEK
        decrypted_mek = self.crypto.decrypt_mek(encrypted_mek, password2, salt)
        assert decrypted_mek != mek


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
