import asyncio
import socket
import ipaddress
import logging
import subprocess
import re
import sys
import json
import os
import argparse

logger = logging.getLogger(__name__)

TIMEOUT = 0.5
CONCURRENCY_LIMIT = 1000

def load_port_config(config_path='ports.json'):
    """
    Загружает конфигурацию портов из JSON файла.
    Returns: (list of ports, dict {port: service_name})
    """
    # Поиск ports.json в корне проекта
    if not os.path.isabs(config_path):
        # Получаем путь к корню проекта (на уровень выше src/)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        config_path = os.path.join(project_root, config_path)

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            ports_dict = json.load(f)

        if ports_dict:
            ports_list = []
            port_to_service = {}

            for port_str, service in ports_dict.items():
                port = int(port_str)
                ports_list.append(port)
                port_to_service[port] = service

            logger.info(f"Loaded {len(ports_list)} ports from {config_path}")
            return ports_list, port_to_service
        else:
            logger.warning(f"Empty ports config in {config_path}")
            return [], {}

    except FileNotFoundError:
        logger.error(f"Ports config file not found: {config_path}")
        return [], {}
    except Exception as e:
        logger.error(f"Failed to load port config: {e}")
        return [], {}

def parse_ports_argument(ports_arg):
    """
    Парсит аргумент --ports и возвращает список портов и словарь port_to_service.
    
    Args:
        ports_arg: строка с портами ('*' для всех портов, '22,80,443' для конкретных)
    
    Returns:
        (list of ports, dict {port: service_name})
    """
    if ports_arg == '*':
        # Все порты от 1 до 65535
        logger.info("Scanning ALL ports (1-65535)")
        all_ports = list(range(1, 65536))
        port_to_service = {port: f'Port-{port}' for port in all_ports}
        return all_ports, port_to_service
    else:
        # Конкретные порты через запятую
        try:
            ports_list = [int(p.strip()) for p in ports_arg.split(',')]
            port_to_service = {port: f'Port-{port}' for port in ports_list}
            logger.info(f"Scanning specified ports: {ports_list}")
            return ports_list, port_to_service
        except ValueError as e:
            logger.error(f"Invalid ports format: {ports_arg}. Use comma-separated numbers or '*'")
            return [], {}

# Глобальные переменные будут установлены в NetworkScanner
TARGET_PORTS = []
PORT_TO_SERVICE = {}

def get_arp_table():
    """
    Parses 'arp -a' output to get IP -> MAC mapping.
    Works on Windows (and Linux relying on arp command).
    Returns: dict {ip_str: mac_str}
    """
    arp_map = {}
    try:
        # Run arp -a
        # Windows encoding might be cp1251 or cp866 for Russian, better decode optimally
        output = subprocess.check_output(['arp', '-a'], stderr=subprocess.DEVNULL)
        
        try:
            output_str = output.decode('cp866')  # Common for RU legacy console
        except UnicodeDecodeError:
            try:
                output_str = output.decode('cp1251')
            except UnicodeDecodeError:
                output_str = output.decode('utf-8', errors='ignore')

        # Regex to find IP and MAC
        # Windows: 192.168.1.1   00-aa-bb-cc-dd-ee   dynamic
        # Linux: ? (192.168.1.1) at 00:aa:bb:cc:dd:ee [ether] on eth0
        
        # Generic regex for IP and MAC (either dash or colon)
        # We look for lines containing IP and MAC
        regex = r'(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})'
        
        for line in output_str.splitlines():
            match = re.search(regex, line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').lower()
                arp_map[ip] = mac
                
    except Exception as e:
        logger.warning(f"Failed to get ARP table: {e}")
        
    return arp_map

class NetworkScanner:
    def __init__(self, ports_arg=None):
        """
        Инициализация сканера.
        
        Args:
            ports_arg: строка с портами ('*' для всех, '22,80,443' для конкретных, None для ports.json)
        """
        global TARGET_PORTS, PORT_TO_SERVICE
        
        if ports_arg is None:
            # Загружаем из ports.json
            TARGET_PORTS, PORT_TO_SERVICE = load_port_config()
        else:
            # Парсим аргумент --ports
            TARGET_PORTS, PORT_TO_SERVICE = parse_ports_argument(ports_arg)
        
        if not TARGET_PORTS:
            logger.warning("No ports to scan!")
        
        self.target_ports = TARGET_PORTS
        self.port_to_service = PORT_TO_SERVICE

    async def _check_port(self, ip, port, sem):
        async with sem:
            try:
                conn = asyncio.open_connection(str(ip), port)
                reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                return True
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return False
            except Exception:
                return False

    async def _scan_host(self, ip, sem):
        """Check which target ports are open on the host and identify services."""
        open_ports = []
        services_set = set()

        for port in self.target_ports:
            if await self._check_port(ip, port, sem):
                open_ports.append(port)
                # Добавляем название сервиса из конфига (без дубликатов)
                service_name = self.port_to_service.get(port, f'Port-{port}')
                services_set.add(service_name)

        if open_ports:
            services = sorted(list(services_set))
            return (str(ip), open_ports, services)
        return None

    async def _run_async_scan(self, hosts):
        sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
        tasks = [self._scan_host(ip, sem) for ip in hosts]
        results = await asyncio.gather(*tasks)
        # Returns dict {ip: (open_ports, services)}
        result_dict = {}
        for result in results:
            if result is not None:
                ip, ports, services = result
                result_dict[ip] = {'ports': ports, 'services': services}
        return result_dict

    def scan_all(self, subnets):
        """
        Scans multiple subnets using asyncio TCP connect.
        Returns a list of dicts: {'ip': ..., 'mac': ..., 'vendor': ...}
        """
        all_hosts = []
        
        # 1. Expand all subnets to unique IPs
        target_ips = set()
        for subnet_str in subnets:
            try:
                network = ipaddress.ip_network(subnet_str, strict=False)
                # Skip network address and broadcast if possible, but keep simple
                for ip in network.hosts():
                    target_ips.add(ip)
            except ValueError:
                logger.error(f"Invalid subnet: {subnet_str}")

        if not target_ips:
            return []

        logger.info(f"Starting discovery scan for {len(target_ips)} targets...")

        # 2. Run Async Scan
        try:
            # Need to run asyncio loop. 
            # If there is already a loop running? (Unlikely in this architecture, but safest to use asyncio.run)
            active_ips = asyncio.run(self._run_async_scan(list(target_ips)))
        except Exception as e:
            logger.error(f"Async scan failed: {e}")
            return []

        logger.info(f"Found {len(active_ips)} active hosts (TCP response). Resolving MACs...")

        # 3. Get ARP table (cache should be warm now)
        arp_table = get_arp_table()

        # 4. Build Result from TCP scan
        active_ips_set = set(active_ips.keys())
        for ip, scan_result in active_ips.items():
            mac = arp_table.get(ip, '')
            vendor = '' # Vendor logic removed as we don't have local OUI db implemented yet

            all_hosts.append({
                'ip': ip,
                'mac': mac,
                'vendor': vendor,
                'status': 'up',
                'open_ports': scan_result['ports'],
                'services': scan_result['services']
            })
        
        # 5. Add hosts from ARP cache that are in target subnets but not found by TCP scan
        arp_only_hosts = []
        for arp_ip in arp_table:
            if arp_ip in active_ips_set:
                continue  # Already added from TCP scan
            try:
                arp_ip_obj = ipaddress.ip_address(arp_ip)
                if arp_ip_obj in target_ips:
                    arp_only_hosts.append({
                        'ip': arp_ip,
                        'mac': arp_table[arp_ip],
                        'vendor': '',
                        'status': 'up (arp only)',
                        'open_ports': [],
                        'services': []
                    })
            except ValueError:
                continue
        
        if arp_only_hosts:
            logger.info(f"Added {len(arp_only_hosts)} hosts from ARP cache (not found by TCP scan)")
            all_hosts.extend(arp_only_hosts)
            
        return all_hosts

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(description="Network Discovery Scanner")
    parser.add_argument('--subnet', required=True, nargs='+', help='Подсеть(и) для сканирования (например: 192.168.0.0/24)')
    parser.add_argument('--ports', help='Порты для сканирования: "*" для всех портов, "22,80,443" для конкретных, или не указывайте для использования ports.json')
    
    args = parser.parse_args()
    
    scanner = NetworkScanner(ports_arg=args.ports)
    hosts = scanner.scan_all(args.subnet)
    
    print(f"\nScan Results ({len(hosts)}):")
    for h in hosts:
        ports = ','.join(map(str, h.get('open_ports', []))) or 'none'
        services = ', '.join(h.get('services', [])) or 'none'
        print(f"IP: {h['ip']:<15} MAC: {h['mac']:<20} Services: {services}")