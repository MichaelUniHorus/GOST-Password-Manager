#!/usr/bin/env python3
"""
Скрипт для создания резервных копий базы данных
"""

import os
import shutil
from datetime import datetime
import argparse


def create_backup(db_path='password_manager.db', backup_dir='backups'):
    """
    Создание резервной копии базы данных
    """
    # Проверка существования БД
    if not os.path.exists(db_path):
        print(f"❌ Ошибка: База данных '{db_path}' не найдена!")
        return False
    
    # Создание директории для бэкапов
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
        print(f"📁 Создана директория для резервных копий: {backup_dir}")
    
    # Генерация имени файла с датой и временем
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_filename = f"password_manager_backup_{timestamp}.db"
    backup_path = os.path.join(backup_dir, backup_filename)
    
    try:
        # Копирование файла
        shutil.copy2(db_path, backup_path)
        
        # Получение размера файла
        size_bytes = os.path.getsize(backup_path)
        size_kb = size_bytes / 1024
        
        print(f"✅ Резервная копия создана успешно!")
        print(f"📄 Файл: {backup_path}")
        print(f"📊 Размер: {size_kb:.2f} KB")
        
        return True
    except Exception as e:
        print(f"❌ Ошибка при создании резервной копии: {e}")
        return False


def list_backups(backup_dir='backups'):
    """
    Список всех резервных копий
    """
    if not os.path.exists(backup_dir):
        print(f"📁 Директория '{backup_dir}' не существует")
        return
    
    backups = [f for f in os.listdir(backup_dir) if f.endswith('.db')]
    
    if not backups:
        print("📁 Резервные копии не найдены")
        return
    
    print(f"\n📋 Найдено резервных копий: {len(backups)}\n")
    print(f"{'Файл':<50} {'Размер':<15} {'Дата создания':<20}")
    print("-" * 85)
    
    for backup in sorted(backups, reverse=True):
        backup_path = os.path.join(backup_dir, backup)
        size_kb = os.path.getsize(backup_path) / 1024
        mtime = datetime.fromtimestamp(os.path.getmtime(backup_path))
        
        print(f"{backup:<50} {size_kb:>10.2f} KB   {mtime.strftime('%Y-%m-%d %H:%M:%S')}")


def restore_backup(backup_file, db_path='password_manager.db'):
    """
    Восстановление из резервной копии
    """
    if not os.path.exists(backup_file):
        print(f"❌ Ошибка: Файл резервной копии '{backup_file}' не найден!")
        return False
    
    # Предупреждение
    if os.path.exists(db_path):
        response = input(f"⚠️  ВНИМАНИЕ: Текущая база данных '{db_path}' будет перезаписана!\n"
                        f"Создать резервную копию текущей БД перед восстановлением? (y/n): ")
        if response.lower() == 'y':
            create_backup(db_path, 'backups/pre_restore')
    
    response = input("Продолжить восстановление? (y/n): ")
    if response.lower() != 'y':
        print("❌ Восстановление отменено")
        return False
    
    try:
        shutil.copy2(backup_file, db_path)
        print(f"✅ База данных успешно восстановлена из {backup_file}")
        return True
    except Exception as e:
        print(f"❌ Ошибка при восстановлении: {e}")
        return False


def cleanup_old_backups(backup_dir='backups', keep_count=10):
    """
    Удаление старых резервных копий, оставляя только последние N
    """
    if not os.path.exists(backup_dir):
        print(f"📁 Директория '{backup_dir}' не существует")
        return
    
    backups = [f for f in os.listdir(backup_dir) if f.endswith('.db')]
    
    if len(backups) <= keep_count:
        print(f"📁 Всего {len(backups)} резервных копий, очистка не требуется")
        return
    
    # Сортировка по времени модификации (старые первыми)
    backups_with_time = []
    for backup in backups:
        backup_path = os.path.join(backup_dir, backup)
        mtime = os.path.getmtime(backup_path)
        backups_with_time.append((backup, mtime))
    
    backups_with_time.sort(key=lambda x: x[1])
    
    # Удаление старых копий
    to_delete = backups_with_time[:-keep_count]
    
    print(f"🗑️  Удаление {len(to_delete)} старых резервных копий...")
    
    for backup, _ in to_delete:
        backup_path = os.path.join(backup_dir, backup)
        try:
            os.remove(backup_path)
            print(f"   ✓ Удалено: {backup}")
        except Exception as e:
            print(f"   ✗ Ошибка при удалении {backup}: {e}")
    
    print(f"✅ Очистка завершена. Осталось {keep_count} последних копий")


def main():
    parser = argparse.ArgumentParser(description='Управление резервными копиями базы данных')
    parser.add_argument('action', choices=['create', 'list', 'restore', 'cleanup'],
                       help='Действие: create (создать), list (список), restore (восстановить), cleanup (очистить старые)')
    parser.add_argument('--db', default='password_manager.db',
                       help='Путь к файлу базы данных (по умолчанию: password_manager.db)')
    parser.add_argument('--backup-dir', default='backups',
                       help='Директория для резервных копий (по умолчанию: backups)')
    parser.add_argument('--file', help='Файл резервной копии для восстановления')
    parser.add_argument('--keep', type=int, default=10,
                       help='Количество резервных копий для сохранения при очистке (по умолчанию: 10)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  🔐 Менеджер резервных копий - Менеджер паролей ГОСТ")
    print("=" * 60)
    print()
    
    if args.action == 'create':
        create_backup(args.db, args.backup_dir)
    elif args.action == 'list':
        list_backups(args.backup_dir)
    elif args.action == 'restore':
        if not args.file:
            print("❌ Ошибка: Укажите файл резервной копии с помощью --file")
            return
        restore_backup(args.file, args.db)
    elif args.action == 'cleanup':
        cleanup_old_backups(args.backup_dir, args.keep)
    
    print()


if __name__ == '__main__':
    main()
