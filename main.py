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
    parser = argparse.ArgumentParser(description="FastScan - Network Scanner")
    parser.add_argument('--config', default='config.yaml', help='Path to config file')
    parser.add_argument('--step', choices=['discovery', 'deep', 'report', 'all'], default='all', help='Step to run')
    parser.add_argument('--force', action='store_true', help='Force rescan of all hosts')
    parser.add_argument('--host', help='Scan specific host IP (for deep scan only)')
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
    
    # Убираем INFO логи от библиотек
    logging.getLogger('pypsexec').setLevel(logging.WARNING)
    logging.getLogger('smbprotocol').setLevel(logging.WARNING)
    # Переносим INFO сообщения paramiko в DEBUG (показываются только в debug режиме)
    if args.debug:
        logging.getLogger('paramiko').setLevel(logging.DEBUG)
    else:
        logging.getLogger('paramiko').setLevel(logging.WARNING)

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

    # 3. Deep Scan Stage
    from src.deep_scan import DeepScanner
    
    if args.step in ['deep', 'all']:
        logger.info("=== Stage 2: Deep Scan ===")
        
        # If specific host is requested
        if args.host:
            ip = args.host
            # Check if host exists in storage, if not create minimal entry
            if ip in storage.data:
                host_info = {'ip': ip}
                host_info.update(storage.data[ip])
                hosts = [host_info]
                logger.info(f"Scanning specific host: {ip}")
            else:
                # Host not in storage, create minimal entry
                # Try to get MAC from ARP table
                from src.discovery import get_arp_table
                arp_table = get_arp_table()
                mac = arp_table.get(ip, '')
                hosts = [{'ip': ip, 'mac': mac, 'vendor': ''}]
                logger.info(f"Scanning new host: {ip}")
        elif not hosts:
            # Load all known IPs from storage
            data = storage.data
            # Convert dict to list of hosts, ensuring minimal required fields
            hosts = []
            for ip, info in data.items():
                host_entry = {'ip': ip}
                host_entry.update(info)
                hosts.append(host_entry)
            
            if hosts:
                logger.info(f"Loaded {len(hosts)} hosts from storage.")
            else:
                logger.warning("No hosts to scan. Run discovery first or use --step all.")
        
        if hosts:
            deep_scanner = DeepScanner(config.get('credentials', []), storage)
            deep_scanner.scan_all(hosts, concurrency=config.get('concurrency', 10), force=args.force or bool(args.host))
            logger.info("Deep scan completed.")

    # 4. Reporting Stage
    if args.step in ['report', 'all']:
        from src.reporting import ReportGenerator
        logger.info("=== Stage 3: Reporting ===")
        reporter = ReportGenerator(storage)
        reporter.generate_all()

if __name__ == "__main__":
    main()
