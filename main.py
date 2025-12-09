import argparse
import yaml
import os
import sys
import logging
from src.config_wizard import create_config
from src.discovery import NetworkScanner

# Logger will be configured in main()
logger = logging.getLogger(__name__)

def load_config(config_path):
    if not os.path.exists(config_path):
        logger.warning(f"Config file {config_path} not found.")
        choice = input("Create new config? [Y/n]: ").strip().lower()
        if choice in ('', 'y', 'yes'):
            return create_config()
        else:
            logger.error("Config file required. Exiting.")
            sys.exit(1)
            
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(description="NetConfGen - Network Scanner")
    parser.add_argument('--config', default='config.yaml', help='Path to config file')
    parser.add_argument('--step', choices=['discovery', 'port-scan', 'connection-check', 'report', 'all'], default='all', help='Step to run')
    parser.add_argument('--force', action='store_true', help='Force rescan of all hosts')
    parser.add_argument('--host', help='Scan specific host IP')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    # Setup Logging based on --debug flag
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Убираем шум от сторонних библиотек
    logging.getLogger('pypsexec').setLevel(logging.WARNING)
    logging.getLogger('smbprotocol').setLevel(logging.WARNING)
    if args.debug:
        logging.getLogger('paramiko').setLevel(logging.DEBUG)
        logging.getLogger('paramiko.transport').setLevel(logging.DEBUG)
    else:
        # Глушим ошибки Paramiko в обычном режиме, показываем только в debug
        logging.getLogger('paramiko').setLevel(logging.CRITICAL)
        logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)

    # Initialize Storage early
    from src.storage import Storage
    storage = Storage()

    # 1. Load Config
    config = load_config(args.config)
    targets = config.get('targets', [])
    if not targets and not args.host:
        logger.error("No targets specified in config.")
        sys.exit(1)

    # 2. Discovery Stage
    hosts = []
    if args.step in ['discovery', 'all'] and not args.host:
        logger.info("=== Stage 1: Discovery ===")
        scanner = NetworkScanner()
        hosts = scanner.scan_all(targets)
        logger.info(f"Total active hosts found: {len(hosts)}")
        
        # Save discovered hosts to storage
        for host in hosts:
            storage.update_host(host['ip'], host)

    # 3. Port Scan Stage
    if args.step in ['port-scan', 'all']:
        from src.port_scan import PortScanner
        logger.info("=== Stage 2: Port Scan ===")
        
        port_scanner = PortScanner(storage)
        
        # Загружаем порты из ports.json
        ports = port_scanner.load_ports_from_file('ports.json')
        if not ports:
            logger.error("Не удалось загрузить порты из ports.json")
            sys.exit(1)
        
        logger.info(f"Загружено портов для сканирования: {len(ports)}")
        
        # If specific host is requested
        if args.host:
            ip = args.host
            # Check if host exists in storage, if not create minimal entry
            if ip not in storage.data:
                # Host not in storage, create minimal entry
                from src.discovery import get_arp_table
                arp_table = get_arp_table()
                mac = arp_table.get(ip, '')
                storage.update_host(ip, {'ip': ip, 'mac': mac, 'vendor': ''})
                logger.info(f"Добавлен новый хост в storage: {ip}")
            
            logger.info(f"Сканирование портов для хоста: {ip}")
            port_scanner.scan_host_ports(ip, ports, timeout=1)
        else:
            # Scan all hosts from storage
            if not storage.data:
                logger.warning("Нет хостов в storage. Запустите сначала discovery или укажите --host")
            else:
                logger.info(f"Сканирование портов для всех хостов из storage: {len(storage.data)} хостов")
                port_scanner.scan_all_hosts(hosts=None, ports=ports, timeout=1, concurrency=config.get('concurrency', 10))
        
        logger.info("Сканирование портов завершено.")
    
    # 4. Connection Check Stage
    if args.step in ['connection-check', 'all']:
        from src.connection_check import ConnectionChecker
        logger.info("=== Stage 3: Connection Check ===")
        
        connection_checker = ConnectionChecker(config.get('credentials', []), storage)
        
        # If specific host is requested
        if args.host:
            ip = args.host
            # Check if host exists in storage
            if ip not in storage.data:
                logger.error(f"Хост {ip} не найден в storage. Запустите сначала port-scan для этого хоста.")
                sys.exit(1)
            
            logger.info(f"Проверка подключения к хосту: {ip}")
            result = connection_checker.check_host_connection(ip, force=args.force)
            if result:
                logger.info("Проверка подключения завершена.")
            else:
                logger.warning(f"Хост {ip} не имеет открытых портов для подключения (SSH:22, WinRM:5985, SMB:445)")
        else:
            # Check all hosts from storage with required ports
            if not storage.data:
                logger.warning("Нет хостов в storage. Запустите сначала discovery и port-scan.")
            else:
                connection_checker.check_all_hosts(hosts=None, concurrency=config.get('concurrency', 20), force=args.force)
                logger.info("Проверка подключения завершена.")

    # 5. Reporting Stage
    if args.step in ['report', 'all']:
        from src.reporting import ReportGenerator
        logger.info("=== Stage 3: Reporting ===")
        reporter = ReportGenerator(storage)
        reporter.generate_all()

if __name__ == "__main__":
    main()
