#!/usr/bin/env python3
"""
Сервис автоматического резервного копирования
Запускается в фоне и создает копии по расписанию
"""

import os
import time
import schedule
from datetime import datetime
from backup import create_backup, cleanup_old_backups
from models import get_database, BackupSettings


class AutoBackupService:
    """Сервис автоматического резервного копирования"""
    
    def __init__(self, db_path='password_manager.db', backup_dir='backups'):
        self.db_path = db_path
        self.backup_dir = backup_dir
        self.db = get_database(db_path)
        self.running = False
    
    def get_settings(self) -> BackupSettings:
        """Получение настроек из БД"""
        session = self.db.get_session()
        settings = session.query(BackupSettings).first()
        
        if not settings:
            # Создать настройки по умолчанию
            settings = BackupSettings(
                enabled=False,
                frequency='daily',
                keep_count=10,
                backup_path='backups'
            )
            session.add(settings)
            session.commit()
        
        session.close()
        return settings
    
    def update_last_backup(self):
        """Обновить время последнего бэкапа"""
        session = self.db.get_session()
        settings = session.query(BackupSettings).first()
        
        if settings:
            settings.last_backup = datetime.utcnow()
            session.commit()
        
        session.close()
    
    def perform_backup(self):
        """Выполнить резервное копирование"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Начало резервного копирования...")
        
        try:
            settings = self.get_settings()
            
            if not settings.enabled:
                print("Автоматическое резервное копирование отключено")
                return
            
            # Создать бэкап
            success = create_backup(self.db_path, settings.backup_path)
            
            if success:
                # Обновить время последнего бэкапа
                self.update_last_backup()
                
                # Очистить старые копии
                cleanup_old_backups(settings.backup_path, settings.keep_count)
                
                print(f"✅ Резервное копирование завершено успешно")
            else:
                print(f"❌ Ошибка при создании резервной копии")
        
        except Exception as e:
            print(f"❌ Ошибка при резервном копировании: {e}")
    
    def schedule_backups(self):
        """Настроить расписание резервного копирования"""
        settings = self.get_settings()
        
        # Очистить предыдущие задачи
        schedule.clear()
        
        if not settings.enabled:
            print("Автоматическое резервное копирование отключено")
            return
        
        # Настроить расписание в зависимости от частоты
        if settings.frequency == 'daily':
            schedule.every().day.at("02:00").do(self.perform_backup)
            print("📅 Резервное копирование запланировано: ежедневно в 02:00")
        
        elif settings.frequency == 'weekly':
            schedule.every().monday.at("02:00").do(self.perform_backup)
            print("📅 Резервное копирование запланировано: еженедельно (понедельник, 02:00)")
        
        elif settings.frequency == 'monthly':
            # Проверка первого числа месяца
            def monthly_backup():
                if datetime.now().day == 1:
                    self.perform_backup()
            
            schedule.every().day.at("02:00").do(monthly_backup)
            print("📅 Резервное копирование запланировано: ежемесячно (1-е число, 02:00)")
        
        else:
            print(f"⚠️ Неизвестная частота: {settings.frequency}")
    
    def start(self):
        """Запустить сервис"""
        print("=" * 60)
        print("  🔐 Сервис автоматического резервного копирования")
        print("=" * 60)
        print()
        
        self.schedule_backups()
        self.running = True
        
        print("✅ Сервис запущен")
        print("Нажмите Ctrl+C для остановки")
        print()
        
        try:
            while self.running:
                schedule.run_pending()
                time.sleep(60)  # Проверка каждую минуту
        
        except KeyboardInterrupt:
            print("\n🛑 Остановка сервиса...")
            self.running = False
    
    def stop(self):
        """Остановить сервис"""
        self.running = False


def main():
    """Главная функция"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Сервис автоматического резервного копирования')
    parser.add_argument('--db', default='password_manager.db', help='Путь к базе данных')
    parser.add_argument('--backup-dir', default='backups', help='Директория для резервных копий')
    parser.add_argument('--test', action='store_true', help='Выполнить тестовый бэкап и выйти')
    
    args = parser.parse_args()
    
    service = AutoBackupService(args.db, args.backup_dir)
    
    if args.test:
        print("🧪 Тестовый режим: выполнение резервного копирования...")
        service.perform_backup()
    else:
        service.start()


if __name__ == '__main__':
    main()
