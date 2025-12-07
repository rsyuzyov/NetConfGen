# FastScan

Инструмент для поиска и классификации хостов в сети

## Возможности

- **Discovery**: Обнаружение активных хостов в сети (Async TCP Connect + ARP).
- **Deep Scan**: Глубокое сканирование обнаруженных хостов через SSH/WinRM/PsExec (сбор информации о системе, дисках, Docker контейнерах и т.д.).
- **Reporting**: Генерация отчетов (HTML/Markdown) на основе собранных данных.
- **Configurable**: Гибкая настройка через `config.yaml`.

### Методы подключения

Для **Linux-хостов**:

- SSH с паролем или ключом

Для **Windows-хостов** (проверяются в следующем порядке):

1. **WinRM с учетными данными** - использует учетные данные из `config.yaml` (NTLM) - _работает на любой ОС_
2. **WinRM SSO** - использует текущие учетные данные пользователя:
   - **Windows**: CredSSP или Kerberos (автоматически)
   - **Linux**: Kerberos (требует настройки `kinit` и `krb5.conf`)
3. **PsExec** - использует учетные данные из `config.yaml` (SMB/RPC) - _работает на любой ОС (через pypsexec)_

## Установка

1.  Клонируйте репозиторий.
2.  Установите зависимости:
    ```bash
    pip install -r requirements.txt
    ```

## Использование

Запуск всех этапов (обнаружение -> сканирование -> отчет):

```bash
python main.py
```

Запуск отдельных этапов:

```bash
# Только обнаружение хостов
python main.py --step discovery

# Только глубокое сканирование (требует список хостов или настроенный config)
python main.py --step deep

# Только генерация отчетов
python main.py --step report
```

## Конфигурация

Настройки хранятся в файле `config.yaml`. Если файла нет, программа предложит создать его при первом запуске.

Пример структуры `config.yaml`:

```yaml
concurrency: 10
targets:
  - 192.168.1.0/24
credentials:
  - user: ag\syuzyov
    type: winrm
    passwords:
      - password1
      - password2
  - user: root
    type: ssh
    passwords:
      - password1
      - "1234567890" # Числовые пароли обязательно обернуть в кавычки!
    key_paths:
      - /path/to/key1
      - /path/to/key2
exclusions: []
```
