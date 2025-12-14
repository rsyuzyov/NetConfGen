# net-conf-gen

Инструмент ищет активные хосты в сети, классифицирует их и формирует конфиги и отчеты:

- ansible inventory
- ssh_config
- файл hosts.txt
- детальные отчеты в формате html, csv, json

## Установка

    ```bash
    chmod +x ./install.sh
    ./install.sh
    ```
    или
    ```batch
    ./install.bat
    ```

## Использование

```bash
python main.py
```
После окончания работы берем данные в подходящем формате в ./output

Пример отчета в формате [html](docs/scan_report_example.html)

Запуск отдельных этапов:

```bash
# Только обнаружение хостов
python main.py --step discovery

# Только глубокое сканирование (требует список хостов или настроенный config)
python main.py --step deep

# Только генерация отчетов
python main.py --step report

# Принудитоельное
python main.py --step report
```


## Конфигурация

Настройки хранятся в файле `config.yaml`. Если файла нет, программа предложит создать его при первом запуске: отвечаем на вопросы. Для прекращения ввод списка просто нажимаем Enter.

Пример структуры `config.yaml`:

```yaml
concurrency: 10
targets:
  - 192.168.1.0/24
credentials:
  - user: domain\username
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
