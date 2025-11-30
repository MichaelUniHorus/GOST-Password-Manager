// Глобальное состояние приложения
let currentEntries = [];
let editingEntryId = null;
let totpIntervals = {};

// API функции
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'include'
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(`/api${endpoint}`, options);
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'Ошибка запроса');
        }
        
        return result;
    } catch (error) {
        throw error;
    }
}

// Проверка инициализации при загрузке
async function checkInitialization() {
    try {
        const result = await apiCall('/init');
        
        if (result.initialized) {
            showScreen('login-screen');
        } else {
            showScreen('init-screen');
        }
    } catch (error) {
        console.error('Ошибка проверки инициализации:', error);
        showScreen('init-screen');
    }
}

// Показ экрана
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.add('hidden');
    });
    document.getElementById(screenId).classList.remove('hidden');
}

// Показ/скрытие ошибок
function showError(elementId, message) {
    const errorEl = document.getElementById(elementId);
    errorEl.textContent = message;
    errorEl.classList.add('show');
}

function hideError(elementId) {
    const errorEl = document.getElementById(elementId);
    errorEl.classList.remove('show');
}

// Инициализация мастер-пароля
document.getElementById('init-btn').addEventListener('click', async () => {
    const password = document.getElementById('init-password').value;
    const confirmPassword = document.getElementById('init-password-confirm').value;
    
    hideError('init-error');
    
    if (!password || !confirmPassword) {
        showError('init-error', 'Заполните все поля');
        return;
    }
    
    if (password !== confirmPassword) {
        showError('init-error', 'Пароли не совпадают');
        return;
    }
    
    if (password.length < 15) {
        showError('init-error', 'Пароль должен содержать минимум 15 символов');
        return;
    }
    
    try {
        await apiCall('/init', 'POST', { master_password: password });
        alert('✅ Мастер-пароль успешно создан!');
        showScreen('login-screen');
    } catch (error) {
        showError('init-error', error.message);
    }
});

// Проверка стойкости пароля при вводе
document.getElementById('init-password').addEventListener('input', (e) => {
    const password = e.target.value;
    const strengthEl = document.getElementById('password-strength');
    
    if (password.length === 0) {
        strengthEl.textContent = '';
        strengthEl.className = 'password-strength';
        return;
    }
    
    let strength = 0;
    let message = '';
    
    if (password.length >= 15) strength++;
    if (password.length >= 20) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    
    if (strength <= 3) {
        strengthEl.className = 'password-strength weak';
        message = '⚠️ Слабый пароль';
    } else if (strength <= 5) {
        strengthEl.className = 'password-strength medium';
        message = '⚡ Средний пароль';
    } else {
        strengthEl.className = 'password-strength strong';
        message = '✅ Надежный пароль';
    }
    
    strengthEl.textContent = message;
});

// Вход
document.getElementById('login-btn').addEventListener('click', async () => {
    const password = document.getElementById('login-password').value;
    
    hideError('login-error');
    
    if (!password) {
        showError('login-error', 'Введите мастер-пароль');
        return;
    }
    
    try {
        await apiCall('/login', 'POST', { master_password: password });
        showScreen('main-screen');
        loadEntries();
    } catch (error) {
        showError('login-error', error.message);
    }
});

// Выход
document.getElementById('logout-btn').addEventListener('click', async () => {
    if (confirm('Вы уверены, что хотите выйти?')) {
        try {
            await apiCall('/logout', 'POST');
            showScreen('login-screen');
            document.getElementById('login-password').value = '';
            currentEntries = [];
        } catch (error) {
            alert('Ошибка выхода: ' + error.message);
        }
    }
});

// Загрузка записей
async function loadEntries() {
    try {
        const result = await apiCall('/entries');
        currentEntries = result.entries;
        renderEntries(currentEntries);
    } catch (error) {
        alert('Ошибка загрузки записей: ' + error.message);
    }
}

// Отображение записей
function renderEntries(entries) {
    const container = document.getElementById('entries-container');
    const emptyState = document.getElementById('empty-state');
    
    if (entries.length === 0) {
        container.innerHTML = '';
        emptyState.classList.remove('hidden');
        return;
    }
    
    emptyState.classList.add('hidden');
    
    container.innerHTML = entries.map(entry => `
        <div class="entry-card ${entry.favorite ? 'favorite' : ''}">
            <div class="entry-header">
                <div class="entry-title">${escapeHtml(entry.site_name)}</div>
                ${entry.url ? `<div class="entry-url">${escapeHtml(entry.url)}</div>` : ''}
            </div>
            
            <div class="entry-field">
                <div class="entry-field-label">Логин</div>
                <div class="entry-field-value">
                    <input type="text" value="${escapeHtml(entry.username)}" readonly>
                    <button class="btn btn-icon" onclick="copyToClipboard('${entry.username}')">📋</button>
                </div>
            </div>
            
            <div class="entry-field">
                <div class="entry-field-label">Пароль</div>
                <div class="entry-field-value">
                    <input type="password" id="pwd-${entry.id}" value="${escapeHtml(entry.password)}" readonly>
                    <button class="btn btn-icon" onclick="togglePasswordVisibility('pwd-${entry.id}')">👁️</button>
                    <button class="btn btn-icon" onclick="copyToClipboard('${entry.password}')">📋</button>
                </div>
            </div>
            
            ${entry.notes ? `
                <div class="entry-field">
                    <div class="entry-field-label">Заметки</div>
                    <div>${escapeHtml(entry.notes)}</div>
                </div>
            ` : ''}
            
            ${entry.has_totp ? `
                <div class="entry-field">
                    <div class="entry-field-label">2FA код</div>
                    <button class="btn btn-secondary" onclick="showTOTP(${entry.id})">Показать TOTP</button>
                </div>
            ` : ''}
            
            <div class="entry-actions">
                <button class="btn btn-secondary" onclick="editEntry(${entry.id})">✏️ Изменить</button>
                <button class="btn btn-danger" onclick="deleteEntry(${entry.id})">🗑️ Удалить</button>
            </div>
        </div>
    `).join('');
}

// Поиск
document.getElementById('search-input').addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase();
    
    if (!query) {
        renderEntries(currentEntries);
        return;
    }
    
    const filtered = currentEntries.filter(entry => 
        entry.site_name.toLowerCase().includes(query) ||
        entry.username.toLowerCase().includes(query) ||
        (entry.url && entry.url.toLowerCase().includes(query))
    );
    
    renderEntries(filtered);
});

// Модальное окно добавления/редактирования
function showAddEntryModal() {
    editingEntryId = null;
    document.getElementById('modal-title').textContent = 'Новая запись';
    document.getElementById('entry-site-name').value = '';
    document.getElementById('entry-url').value = '';
    document.getElementById('entry-username').value = '';
    document.getElementById('entry-password').value = '';
    document.getElementById('entry-notes').value = '';
    document.getElementById('entry-totp').value = '';
    document.getElementById('entry-favorite').checked = false;
    hideError('entry-error');
    document.getElementById('entry-modal').classList.remove('hidden');
}

function closeEntryModal() {
    document.getElementById('entry-modal').classList.add('hidden');
}

function editEntry(id) {
    const entry = currentEntries.find(e => e.id === id);
    if (!entry) return;
    
    editingEntryId = id;
    document.getElementById('modal-title').textContent = 'Редактирование записи';
    document.getElementById('entry-site-name').value = entry.site_name;
    document.getElementById('entry-url').value = entry.url || '';
    document.getElementById('entry-username').value = entry.username;
    document.getElementById('entry-password').value = entry.password;
    document.getElementById('entry-notes').value = entry.notes || '';
    document.getElementById('entry-totp').value = '';
    document.getElementById('entry-favorite').checked = entry.favorite;
    hideError('entry-error');
    document.getElementById('entry-modal').classList.remove('hidden');
}

document.getElementById('add-entry-btn').addEventListener('click', showAddEntryModal);

document.getElementById('save-entry-btn').addEventListener('click', async () => {
    const data = {
        site_name: document.getElementById('entry-site-name').value,
        url: document.getElementById('entry-url').value,
        username: document.getElementById('entry-username').value,
        password: document.getElementById('entry-password').value,
        notes: document.getElementById('entry-notes').value,
        totp_secret: document.getElementById('entry-totp').value,
        favorite: document.getElementById('entry-favorite').checked
    };
    
    hideError('entry-error');
    
    if (!data.site_name || !data.username || !data.password) {
        showError('entry-error', 'Заполните обязательные поля');
        return;
    }
    
    try {
        if (editingEntryId) {
            await apiCall(`/entries/${editingEntryId}`, 'PUT', data);
        } else {
            await apiCall('/entries', 'POST', data);
        }
        
        closeEntryModal();
        loadEntries();
    } catch (error) {
        showError('entry-error', error.message);
    }
});

async function deleteEntry(id) {
    if (!confirm('Вы уверены, что хотите удалить эту запись?')) {
        return;
    }
    
    try {
        await apiCall(`/entries/${id}`, 'DELETE');
        loadEntries();
    } catch (error) {
        alert('Ошибка удаления: ' + error.message);
    }
}

// Генератор паролей
function generatePassword() {
    document.getElementById('generator-modal').classList.remove('hidden');
    generatePasswordInModal();
}

function closeGeneratorModal() {
    document.getElementById('generator-modal').classList.add('hidden');
}

async function generatePasswordInModal() {
    const length = parseInt(document.getElementById('gen-length').value);
    const useUppercase = document.getElementById('gen-uppercase').checked;
    const useLowercase = document.getElementById('gen-lowercase').checked;
    const useDigits = document.getElementById('gen-digits').checked;
    const useSymbols = document.getElementById('gen-symbols').checked;
    
    try {
        const result = await apiCall('/generate-password', 'POST', {
            length,
            use_uppercase: useUppercase,
            use_lowercase: useLowercase,
            use_digits: useDigits,
            use_symbols: useSymbols
        });
        
        document.getElementById('generated-password').value = result.password;
    } catch (error) {
        alert('Ошибка генерации: ' + error.message);
    }
}

function useGeneratedPassword() {
    const password = document.getElementById('generated-password').value;
    document.getElementById('entry-password').value = password;
    closeGeneratorModal();
}

document.getElementById('gen-length').addEventListener('input', (e) => {
    document.getElementById('length-value').textContent = e.target.value;
});

// TOTP
async function showTOTP(entryId) {
    try {
        const result = await apiCall(`/totp/${entryId}`);
        
        const entry = currentEntries.find(e => e.id === entryId);
        const message = `
            <div style="text-align: center;">
                <h3>${entry.site_name}</h3>
                <div class="totp-code">${result.code}</div>
                <div class="totp-timer">Обновится через ${result.remaining_seconds} сек</div>
            </div>
        `;
        
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 400px;">
                <div class="modal-header">
                    <h2>2FA код</h2>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                </div>
                <div class="modal-body">${message}</div>
                <div class="modal-footer">
                    <button class="btn btn-primary" onclick="copyToClipboard('${result.code}'); this.textContent='✅ Скопировано'">📋 Копировать</button>
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Закрыть</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Автообновление кода
        const interval = setInterval(async () => {
            try {
                const newResult = await apiCall(`/totp/${entryId}`);
                const codeEl = modal.querySelector('.totp-code');
                const timerEl = modal.querySelector('.totp-timer');
                if (codeEl && timerEl) {
                    codeEl.textContent = newResult.code;
                    timerEl.textContent = `Обновится через ${newResult.remaining_seconds} сек`;
                }
            } catch (error) {
                clearInterval(interval);
            }
        }, 1000);
        
        modal.addEventListener('remove', () => clearInterval(interval));
        
    } catch (error) {
        alert('Ошибка получения TOTP: ' + error.message);
    }
}

// Аудит
document.getElementById('audit-btn').addEventListener('click', async () => {
    try {
        const result = await apiCall('/audit-logs?limit=50');
        
        const logsHtml = result.logs.map(log => `
            <div class="audit-log-item">
                <div class="audit-log-action">${escapeHtml(log.action)}</div>
                <div class="audit-log-time">${new Date(log.timestamp).toLocaleString('ru-RU')}</div>
                <div>IP: ${escapeHtml(log.ip_address)}</div>
                ${log.entry_id ? `<div>ID записи: ${log.entry_id}</div>` : ''}
                <div class="${log.success ? 'audit-log-success' : 'audit-log-fail'}">
                    ${log.success ? '✅ Успешно' : '❌ Ошибка'}
                </div>
            </div>
        `).join('');
        
        document.getElementById('audit-logs').innerHTML = logsHtml || '<p>Нет записей</p>';
        document.getElementById('audit-modal').classList.remove('hidden');
    } catch (error) {
        alert('Ошибка загрузки логов: ' + error.message);
    }
});

function closeAuditModal() {
    document.getElementById('audit-modal').classList.add('hidden');
}

// Утилиты
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    input.type = input.type === 'password' ? 'text' : 'password';
}

function copyToClipboard(text) {
    if (typeof text === 'object') {
        text = document.getElementById(text).value;
    }
    
    navigator.clipboard.writeText(text).then(() => {
        // Временное уведомление
        const notification = document.createElement('div');
        notification.textContent = '✅ Скопировано в буфер обмена';
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #16a34a;
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            z-index: 10000;
        `;
        document.body.appendChild(notification);
        setTimeout(() => notification.remove(), 2000);
    }).catch(err => {
        alert('Ошибка копирования: ' + err);
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Инициализация при загрузке
document.addEventListener('DOMContentLoaded', () => {
    checkInitialization();
});

// Автоблокировка при неактивности
let inactivityTimer;
function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(() => {
        if (document.getElementById('main-screen').classList.contains('hidden') === false) {
            alert('⏰ Сессия завершена из-за неактивности');
            document.getElementById('logout-btn').click();
        }
    }, 5 * 60 * 1000); // 5 минут
}

document.addEventListener('mousemove', resetInactivityTimer);
document.addEventListener('keypress', resetInactivityTimer);
resetInactivityTimer();

// ========== Смена мастер-пароля ==========

function openChangePasswordModal() {
    document.getElementById('change-password-modal').classList.remove('hidden');
    document.getElementById('current-master-password').value = '';
    document.getElementById('new-master-password').value = '';
    document.getElementById('confirm-master-password').value = '';
    document.getElementById('change-password-error').textContent = '';
}

function closeChangePasswordModal() {
    document.getElementById('change-password-modal').classList.add('hidden');
}

async function submitChangeMasterPassword() {
    const currentPassword = document.getElementById('current-master-password').value;
    const newPassword = document.getElementById('new-master-password').value;
    const confirmPassword = document.getElementById('confirm-master-password').value;
    const errorDiv = document.getElementById('change-password-error');
    
    errorDiv.textContent = '';
    
    // Валидация
    if (!currentPassword || !newPassword || !confirmPassword) {
        errorDiv.textContent = 'Заполните все поля';
        return;
    }
    
    if (newPassword.length < 15) {
        errorDiv.textContent = 'Новый пароль должен содержать минимум 15 символов';
        return;
    }
    
    if (newPassword !== confirmPassword) {
        errorDiv.textContent = 'Новый пароль и подтверждение не совпадают';
        return;
    }
    
    if (currentPassword === newPassword) {
        errorDiv.textContent = 'Новый пароль должен отличаться от текущего';
        return;
    }
    
    try {
        const response = await fetch('/api/change-master-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert('✅ Мастер-пароль успешно изменен!\n\nВы будете перенаправлены на страницу входа.');
            closeChangePasswordModal();
            closeSettingsModal();
            logout();
        } else {
            errorDiv.textContent = data.error || 'Ошибка смены пароля';
        }
    } catch (error) {
        errorDiv.textContent = 'Ошибка соединения с сервером';
        console.error('Error changing password:', error);
    }
}

// Проверка стойкости нового пароля
document.getElementById('new-master-password')?.addEventListener('input', (e) => {
    const password = e.target.value;
    const strengthDiv = document.getElementById('new-password-strength');
    
    if (password.length === 0) {
        strengthDiv.textContent = '';
        return;
    }
    
    let strength = 0;
    let feedback = [];
    
    if (password.length >= 15) strength++;
    if (password.length >= 20) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    
    if (password.length < 15) {
        feedback.push('Минимум 15 символов');
    }
    if (!/[a-z]/.test(password)) {
        feedback.push('Добавьте строчные буквы');
    }
    if (!/[A-Z]/.test(password)) {
        feedback.push('Добавьте заглавные буквы');
    }
    if (!/[0-9]/.test(password)) {
        feedback.push('Добавьте цифры');
    }
    if (!/[^a-zA-Z0-9]/.test(password)) {
        feedback.push('Добавьте спецсимволы');
    }
    
    let strengthText = '';
    let strengthClass = '';
    
    if (strength <= 2) {
        strengthText = '❌ Слабый';
        strengthClass = 'weak';
    } else if (strength <= 4) {
        strengthText = '⚠️ Средний';
        strengthClass = 'medium';
    } else {
        strengthText = '✅ Сильный';
        strengthClass = 'strong';
    }
    
    strengthDiv.textContent = `${strengthText}${feedback.length > 0 ? ': ' + feedback.join(', ') : ''}`;
    strengthDiv.className = `password-strength ${strengthClass}`;
});

// ========== Настройки ==========

function openSettingsModal() {
    document.getElementById('settings-modal').classList.remove('hidden');
    loadBackupSettings();
}

function closeSettingsModal() {
    document.getElementById('settings-modal').classList.add('hidden');
}

async function loadBackupSettings() {
    try {
        const response = await fetch('/api/backup-settings');
        const data = await response.json();
        
        document.getElementById('backup-enabled').checked = data.enabled;
        document.getElementById('backup-frequency').value = data.frequency;
        document.getElementById('backup-keep-count').value = data.keep_count;
        document.getElementById('backup-path').textContent = data.backup_path;
        
        if (data.last_backup) {
            const date = new Date(data.last_backup);
            document.getElementById('last-backup-time').textContent = date.toLocaleString('ru-RU');
        } else {
            document.getElementById('last-backup-time').textContent = 'Никогда';
        }
    } catch (error) {
        console.error('Error loading backup settings:', error);
    }
}

async function updateBackupSettings() {
    const enabled = document.getElementById('backup-enabled').checked;
    const frequency = document.getElementById('backup-frequency').value;
    const keepCount = parseInt(document.getElementById('backup-keep-count').value);
    
    try {
        const response = await fetch('/api/backup-settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                enabled: enabled,
                frequency: frequency,
                keep_count: keepCount
            })
        });
        
        if (response.ok) {
            showNotification('✅ Настройки сохранены');
        } else {
            showNotification('❌ Ошибка сохранения настроек');
        }
    } catch (error) {
        console.error('Error updating backup settings:', error);
        showNotification('❌ Ошибка соединения');
    }
}

async function createManualBackup() {
    showNotification('💾 Создание резервной копии...');
    
    try {
        const response = await fetch('/api/backup', {
            method: 'POST'
        });
        
        if (response.ok) {
            showNotification('✅ Резервная копия создана');
            loadBackupSettings(); // Обновить время последнего бэкапа
        } else {
            showNotification('❌ Ошибка создания копии');
        }
    } catch (error) {
        console.error('Error creating backup:', error);
        showNotification('❌ Ошибка соединения');
    }
}

function showNotification(message) {
    // Простое уведомление через alert (можно улучшить)
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4CAF50;
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}
