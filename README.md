# net-conf-gen

Инструмент ищет активные хосты в сети, классифицирует их и формирует конфиги и отчеты:

- ansible inventory
- ssh_config
- файл hosts.txt
- детальные отчеты в формате [html](https://htmlpreview.github.io/?https://github.com/rsyuzyov/net-conf-gen/blob/main/docs/scan_report_example.html), csv, json

## Установка

Установка зависимостей на linux:
```bash
chmod +x ./install.sh && ./install.sh
```
Установка python (если не установлен) и зависимостей на windows:
```batch
./install.bat
```

## Использование

```bash
python main.py
```
При первом запуске скрипт предложит сгенерировать конфиг (./config.yaml) - отвечаем на вопросы. Для прекращения ввод списка просто нажимаем Enter.  
Можно заранее создать руками копированием из [config.yaml.example](./config.yaml.example)  
Далее создаст ./output/scan_state.json - главный файл, дополняемый на каждом этапе работы  
После окончания работы берем данные в подходящем формате в ./output  
Пример отчета в формате [html](https://htmlpreview.github.io/?https://github.com/rsyuzyov/net-conf-gen/blob/main/docs/scan_report_example.html)  

Варианты запуска:

```bash
# Справка
python main.py --help

# Только обнаружение списка хостов (быстро)
python main.py --step discovery

# Только проверка подключений (требует результаты discovery или config)
python main.py --step connection-check

# Только фингерпринтинг (требует результаты discovery или config)
python main.py --step fingerprint

# Только генерация отчетов
python main.py --step report

# Принудительное сканирование одного хоста
python main.py --host 10.0.0.1 --force --debug
```
