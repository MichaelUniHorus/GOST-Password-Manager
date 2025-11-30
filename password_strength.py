"""
Модуль для улучшенной оценки стойкости паролей
Использует zxcvbn для более точной оценки
"""

from zxcvbn import zxcvbn
from typing import Dict, Tuple


class PasswordStrengthAnalyzer:
    """
    Анализатор стойкости паролей с использованием zxcvbn
    """
    
    def analyze(self, password: str, user_inputs: list = None) -> Dict:
        """
        Анализ стойкости пароля
        
        Args:
            password: Пароль для анализа
            user_inputs: Список пользовательских данных (имя, email и т.д.)
        
        Returns:
            Dict с результатами анализа
        """
        if not password:
            return {
                'score': 0,
                'level': 'very_weak',
                'crack_time': 'мгновенно',
                'suggestions': ['Пароль не может быть пустым'],
                'warning': 'Пароль отсутствует'
            }
        
        # Анализ с помощью zxcvbn
        result = zxcvbn(password, user_inputs=user_inputs or [])
        
        # Маппинг уровней
        level_map = {
            0: 'very_weak',
            1: 'weak',
            2: 'medium',
            3: 'strong',
            4: 'very_strong'
        }
        
        # Перевод времени взлома
        crack_time = self._translate_crack_time(result['crack_times_display']['offline_slow_hashing_1e4_per_second'])
        
        # Перевод предупреждений и советов
        warning = self._translate_warning(result.get('feedback', {}).get('warning', ''))
        suggestions = self._translate_suggestions(result.get('feedback', {}).get('suggestions', []))
        
        return {
            'score': result['score'] * 25,  # 0-100
            'level': level_map[result['score']],
            'crack_time': crack_time,
            'suggestions': suggestions,
            'warning': warning,
            'guesses': result['guesses'],
            'guesses_log10': result['guesses_log10']
        }
    
    def _translate_crack_time(self, time_str: str) -> str:
        """Перевод времени взлома на русский"""
        translations = {
            'less than a second': 'менее секунды',
            'instant': 'мгновенно',
            'seconds': 'секунды',
            'minutes': 'минуты',
            'hours': 'часы',
            'days': 'дни',
            'months': 'месяцы',
            'years': 'годы',
            'centuries': 'столетия'
        }
        
        result = time_str.lower()
        for eng, rus in translations.items():
            result = result.replace(eng, rus)
        
        return result
    
    def _translate_warning(self, warning: str) -> str:
        """Перевод предупреждений на русский"""
        if not warning:
            return ''
        
        translations = {
            'This is a top-10 common password': 'Это один из 10 самых распространенных паролей',
            'This is a top-100 common password': 'Это один из 100 самых распространенных паролей',
            'This is a very common password': 'Это очень распространенный пароль',
            'This is similar to a commonly used password': 'Это похоже на часто используемый пароль',
            'A word by itself is easy to guess': 'Отдельное слово легко угадать',
            'Names and surnames by themselves are easy to guess': 'Имена и фамилии сами по себе легко угадать',
            'Common names and surnames are easy to guess': 'Распространенные имена и фамилии легко угадать',
            'Straight rows of keys are easy to guess': 'Последовательности клавиш легко угадать',
            'Short keyboard patterns are easy to guess': 'Короткие паттерны клавиатуры легко угадать',
            'Repeats like "aaa" are easy to guess': 'Повторы типа "ааа" легко угадать',
            'Repeats like "abcabcabc" are only slightly harder to guess than "abc"': 'Повторы типа "abcabcabc" ненамного сложнее, чем "abc"',
            'Sequences like abc or 6543 are easy to guess': 'Последовательности типа abc или 6543 легко угадать',
            'Recent years are easy to guess': 'Недавние годы легко угадать',
            'Dates are often easy to guess': 'Даты часто легко угадать'
        }
        
        return translations.get(warning, warning)
    
    def _translate_suggestions(self, suggestions: list) -> list:
        """Перевод советов на русский"""
        if not suggestions:
            return []
        
        translations = {
            'Use a few words, avoid common phrases': 'Используйте несколько слов, избегайте распространенных фраз',
            'No need for symbols, digits, or uppercase letters': 'Не обязательно использовать символы, цифры или заглавные буквы',
            'Add another word or two. Uncommon words are better.': 'Добавьте еще одно-два слова. Необычные слова лучше.',
            'Capitalization doesn\'t help very much': 'Заглавные буквы не очень помогают',
            'All-uppercase is almost as easy to guess as all-lowercase': 'Все заглавные почти так же легко угадать, как все строчные',
            'Reversed words aren\'t much harder to guess': 'Перевернутые слова ненамного сложнее угадать',
            'Predictable substitutions like \'@\' instead of \'a\' don\'t help very much': 'Предсказуемые замены вроде "@" вместо "a" не очень помогают',
            'Use a longer keyboard pattern with more turns': 'Используйте более длинный паттерн клавиатуры с большим количеством поворотов',
            'Avoid repeated words and characters': 'Избегайте повторяющихся слов и символов',
            'Avoid sequences': 'Избегайте последовательностей',
            'Avoid recent years': 'Избегайте недавних годов',
            'Avoid years that are associated with you': 'Избегайте годов, связанных с вами',
            'Avoid dates and years that are associated with you': 'Избегайте дат и годов, связанных с вами'
        }
        
        return [translations.get(s, s) for s in suggestions]
    
    def get_strength_color(self, level: str) -> str:
        """Получить цвет для уровня стойкости"""
        colors = {
            'very_weak': '#ef4444',  # red
            'weak': '#f59e0b',       # orange
            'medium': '#eab308',     # yellow
            'strong': '#10b981',     # green
            'very_strong': '#059669' # dark green
        }
        return colors.get(level, '#64748b')
    
    def get_strength_label(self, level: str) -> str:
        """Получить текстовую метку для уровня стойкости"""
        labels = {
            'very_weak': 'Очень слабый',
            'weak': 'Слабый',
            'medium': 'Средний',
            'strong': 'Сильный',
            'very_strong': 'Очень сильный'
        }
        return labels.get(level, 'Неизвестно')


# Singleton instance
_analyzer_instance = None

def get_password_analyzer() -> PasswordStrengthAnalyzer:
    """Получение singleton экземпляра анализатора"""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = PasswordStrengthAnalyzer()
    return _analyzer_instance
