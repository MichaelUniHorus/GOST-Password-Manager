"""
Модуль для проверки паролей на утечки через Have I Been Pwned API
Использует k-anonymity модель для безопасной проверки
"""

import hashlib
import requests
from typing import Tuple


class BreachChecker:
    """
    Проверка паролей на утечки через HIBP API
    """
    
    API_URL = "https://api.pwnedpasswords.com/range/"
    
    def check_password(self, password: str) -> Tuple[bool, int]:
        """
        Проверка пароля на утечки
        
        Использует k-anonymity: отправляет только первые 5 символов SHA-1 хэша,
        получает список всех хэшей с таким префиксом, проверяет локально
        
        Args:
            password: Пароль для проверки
        
        Returns:
            Tuple[is_breached, breach_count]
            - is_breached: True если пароль найден в утечках
            - breach_count: Количество раз, когда пароль был найден
        """
        if not password:
            return False, 0
        
        # Вычисляем SHA-1 хэш пароля
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Берем первые 5 символов для k-anonymity
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            # Запрос к API
            response = requests.get(
                f"{self.API_URL}{prefix}",
                timeout=5,
                headers={'User-Agent': 'GOST-Password-Manager/1.2'}
            )
            
            if response.status_code != 200:
                # Если API недоступен, возвращаем безопасное значение
                return False, 0
            
            # Парсим ответ
            hashes = response.text.splitlines()
            
            for hash_line in hashes:
                # Формат: SUFFIX:COUNT
                hash_suffix, count = hash_line.split(':')
                
                if hash_suffix == suffix:
                    # Пароль найден в утечках!
                    return True, int(count)
            
            # Пароль не найден в утечках
            return False, 0
            
        except requests.RequestException as e:
            # Ошибка сети - возвращаем безопасное значение
            print(f"Ошибка проверки утечек: {e}")
            return False, 0
        except Exception as e:
            print(f"Неожиданная ошибка при проверке утечек: {e}")
            return False, 0
    
    def check_password_hash(self, sha1_hash: str) -> Tuple[bool, int]:
        """
        Проверка по готовому SHA-1 хэшу
        
        Args:
            sha1_hash: SHA-1 хэш пароля (hex string)
        
        Returns:
            Tuple[is_breached, breach_count]
        """
        sha1_hash = sha1_hash.upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            response = requests.get(
                f"{self.API_URL}{prefix}",
                timeout=5,
                headers={'User-Agent': 'GOST-Password-Manager/1.2'}
            )
            
            if response.status_code != 200:
                return False, 0
            
            hashes = response.text.splitlines()
            
            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                if hash_suffix == suffix:
                    return True, int(count)
            
            return False, 0
            
        except Exception as e:
            print(f"Ошибка проверки хэша: {e}")
            return False, 0
    
    def get_breach_severity(self, count: int) -> str:
        """
        Определить серьезность утечки по количеству
        
        Args:
            count: Количество раз в утечках
        
        Returns:
            Уровень серьезности: low, medium, high, critical
        """
        if count == 0:
            return 'none'
        elif count < 10:
            return 'low'
        elif count < 100:
            return 'medium'
        elif count < 1000:
            return 'high'
        else:
            return 'critical'
    
    def get_breach_message(self, is_breached: bool, count: int) -> str:
        """
        Получить сообщение о статусе утечки
        
        Args:
            is_breached: Найден ли пароль в утечках
            count: Количество раз
        
        Returns:
            Текстовое сообщение
        """
        if not is_breached:
            return "✅ Пароль не найден в известных утечках"
        
        severity = self.get_breach_severity(count)
        
        messages = {
            'low': f"⚠️ Пароль найден в утечках {count} раз (низкий риск)",
            'medium': f"⚠️ Пароль найден в утечках {count} раз (средний риск)",
            'high': f"🔴 Пароль найден в утечках {count} раз (высокий риск)",
            'critical': f"🔴 Пароль найден в утечках {count} раз (критический риск!)"
        }
        
        return messages.get(severity, f"⚠️ Пароль найден в утечках {count} раз")


# Singleton instance
_checker_instance = None

def get_breach_checker() -> BreachChecker:
    """Получение singleton экземпляра проверки утечек"""
    global _checker_instance
    if _checker_instance is None:
        _checker_instance = BreachChecker()
    return _checker_instance
