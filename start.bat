@echo off
echo ========================================
echo   Менеджер паролей ГОСТ
echo ========================================
echo.

REM Проверка виртуального окружения
if not exist "venv\Scripts\activate.bat" (
    echo [1/3] Создание виртуального окружения...
    python -m venv venv
    if errorlevel 1 (
        echo Ошибка: Не удалось создать виртуальное окружение
        echo Убедитесь, что Python 3.9+ установлен
        pause
        exit /b 1
    )
)

REM Активация виртуального окружения
echo [2/3] Активация виртуального окружения...
call venv\Scripts\activate.bat

REM Установка зависимостей
echo [3/3] Проверка зависимостей...
pip install -q -r requirements.txt
if errorlevel 1 (
    echo Ошибка: Не удалось установить зависимости
    pause
    exit /b 1
)

REM Проверка .env файла
if not exist ".env" (
    echo.
    echo ВНИМАНИЕ: Файл .env не найден!
    echo Создаю из .env.example...
    copy .env.example .env
    echo.
    echo Пожалуйста, отредактируйте .env файл перед использованием!
    echo.
)

echo.
echo ========================================
echo   Запуск приложения...
echo ========================================
echo.
echo Приложение будет доступно по адресу:
echo https://127.0.0.1:5000
echo.
echo Нажмите Ctrl+C для остановки
echo ========================================
echo.

REM Запуск приложения
python app.py

pause
