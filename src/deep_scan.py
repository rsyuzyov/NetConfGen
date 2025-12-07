import logging
import concurrent.futures
import socket

from .connectors.ssh import SSHConnector
from .connectors.winrm import WinRMConnector
from .connectors.psexec import PsExecConnector
from .fingerprinting import Fingerprinter
from .credentials import CredentialManager
from .discovery import TARGET_PORTS, PORT_TO_SERVICE

logger = logging.getLogger(__name__)

class DeepScanner:
    def __init__(self, credentials, storage):
        self.storage = storage
        
        # Helper modules
        self.fingerprinter = Fingerprinter()
        self.credential_manager = CredentialManager(credentials)
        
        # Connectors
        self.ssh_connector = SSHConnector()
        self.winrm_connector = WinRMConnector()
        self.psexec_connector = PsExecConnector()

    def _check_port(self, ip, port, timeout=1):
        """Check if a TCP port is open."""
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _check_multiple_ports(self, ip, ports, timeout=1):
        """
        Параллельная проверка нескольких портов.
        
        Args:
            ip: IP адрес хоста
            ports: список портов для проверки
            timeout: таймаут для каждого порта
            
        Returns:
            dict: {port: True/False}
        """
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port, result == 0
            except:
                return port, False
        
        results = {}
        with ThreadPoolExecutor(max_workers=len(ports)) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                results[port] = is_open
        
        return results

    def scan_host(self, host_info, force=False):
        ip = host_info['ip']

        # Check cache - but always refresh open_ports
        if not force and self.storage.is_scanned(ip):
            logger.debug(f"Skipping {ip} (already scanned, refreshing open_ports)")
            cached_result = self.storage.get_host(ip)

            # Refresh open_ports for cached hosts
            existing_ports = set(host_info.get('open_ports', []) or [])
            all_port_status = self._check_multiple_ports(ip, TARGET_PORTS, timeout=1)
            newly_found_ports = [port for port, is_open in all_port_status.items() if is_open]
            open_ports = sorted(set(existing_ports) | set(newly_found_ports))

            # Update services based on open_ports (without duplicates)
            services_set = set()
            for port in open_ports:
                service_name = PORT_TO_SERVICE.get(port, f'Port-{port}')
                services_set.add(service_name)
            services = sorted(list(services_set))

            # Update open_ports and services in cached result
            cached_result['open_ports'] = open_ports
            cached_result['services'] = services
            self.storage.update_host(ip, {'open_ports': open_ports, 'services': services})

            return cached_result

        logger.info(f"Deep scanning {ip}...")
        result = {
            'ip': ip,
            'mac': host_info.get('mac'),
            'vendor': host_info.get('vendor'),
            'hostname': '',
            'os': '',
            'type': 'unknown',
            'deep_scan_status': 'failed',
            'auth_method': None,
            'auth_attempts': []
        }

        # Параллельная проверка ключевых портов для определения типа хоста
        key_ports = [22, 445, 135, 3389, 5985, 8291, 8728]
        port_status = self._check_multiple_ports(ip, key_ports, timeout=1)

        # Определяем тип хоста по открытым портам
        is_windows = port_status.get(445) or port_status.get(5985) or port_status.get(3389)
        # Также проверяем сохраненный тип хоста
        if not is_windows:
            existing_host = self.storage.get_host(ip)
            if existing_host and existing_host.get('type') == 'windows':
                is_windows = True
        
        is_linux = port_status.get(22)
        is_mikrotik = port_status.get(8291) or port_status.get(8728)  # Winbox или API port

        logger.debug(f"{ip}: Port status: {port_status}, Windows={is_windows}, Linux={is_linux}, MikroTik={is_mikrotik}")

        # Сканируем все целевые порты для сохранения в open_ports
        # Используем те же порты, что и в discovery.py

        # Начинаем с существующих open_ports, если они есть
        existing_ports = set(host_info.get('open_ports', []) or [])
        if existing_ports:
            logger.debug(f"{ip}: Existing open_ports: {sorted(existing_ports)}")

        # Сканируем все целевые порты
        all_port_status = self._check_multiple_ports(ip, TARGET_PORTS, timeout=1)
        newly_found_ports = [port for port, is_open in all_port_status.items() if is_open]
        
        # Объединяем существующие и новые порты (без дубликатов)
        open_ports = sorted(set(existing_ports) | set(newly_found_ports))
        
        # Формируем список служб из открытых портов (без дубликатов)
        services_set = set()
        for port in open_ports:
            service_name = PORT_TO_SERVICE.get(port, f'Port-{port}')
            services_set.add(service_name)
        services = sorted(list(services_set))
        
        if newly_found_ports:
            added_ports = sorted(set(newly_found_ports) - existing_ports)
            if added_ports:
                logger.debug(f"{ip}: Added new open ports: {added_ports}")
            logger.debug(f"{ip}: All open ports after scan: {open_ports}")
        elif not existing_ports:
            logger.debug(f"{ip}: Scanned all ports, found open: {open_ports}")
        
        result['open_ports'] = open_ports
        result['services'] = services

        # Если обнаружен порт Winbox (8291), это MikroTik
        if is_mikrotik:
            result['os'] = 'RouterOS'
            result['type'] = 'network'
            result['device_type'] = 'mikrotik'
            logger.debug(f"{ip}: Identified as MikroTik (Winbox port 8291 open)")

        # Cache port status to avoid re-checking and duplicate logging
        # port -> bool (True if open, False if closed)
        port_cache = port_status.copy()

        def check_port_once(port, method_name):
            """Check port and log if closed (only once)."""
            if port in port_cache:
                return port_cache[port]
            
            is_open = self._check_port(ip, port)
            port_cache[port] = is_open
            
            if not is_open:
                result['auth_attempts'].append({
                    'method': method_name,
                    'status': 'skipped',
                    'error': f'Port {port} closed'
                })
            return is_open

        # Приоритизация коннекторов
        auth_attempts = []

        if is_windows:
            # Windows хост - пробуем WinRM SSO первым (самый быстрый)
            auth_attempts.extend(['winrm_sso', 'winrm', 'psexec'])
        elif is_linux:
            # Linux хост - пробуем SSH ключи первыми
            auth_attempts.extend(['ssh_key', 'ssh'])
        else:
            # Неизвестный тип - только SSH (WinRM и PSExec только для Windows)
            auth_attempts.extend(['ssh'])

        # Перебор коннекторов с приоритизацией
        for connector_type in auth_attempts:
            if connector_type == 'winrm_sso':
                # Try WinRM SSO (CredSSP on Windows, Kerberos on Windows/Linux with kinit)
                # Only for Windows hosts
                if not is_windows:
                    logger.debug(f"{ip}: Skipping WinRM SSO - not a Windows host")
                    continue
                if check_port_once(5985, 'winrm_sso'):
                    try:
                        logger.debug(f"Trying WinRM SSO for {ip}...")
                        info = self.winrm_connector.connect(ip, user=None, password=None)
                        if info:
                            # Сохраняем существующий vendor из storage перед обновлением
                            existing_host = self.storage.get_host(ip)
                            existing_vendor = existing_host.get('vendor', '')
                            if existing_vendor and not result.get('vendor'):
                                result['vendor'] = existing_vendor
                            
                            result.update(info)
                            
                            # Если vendor все еще не установлен, пытаемся получить из MAC
                            # Используем MAC из os_info, если доступен, иначе из result
                            mac_for_vendor = None
                            if info.get('os_info', {}).get('mac'):
                                mac_for_vendor = info['os_info']['mac']
                            elif result.get('mac'):
                                mac_for_vendor = result.get('mac')
                            
                            if not result.get('vendor') and mac_for_vendor:
                                vendor = self.fingerprinter.get_vendor_from_mac(mac_for_vendor)
                                if vendor:
                                    result['vendor'] = vendor
                            result['deep_scan_status'] = 'completed'
                            result['auth_method'] = 'winrm_sso'
                            logger.debug(f"{ip}: Successful authentication via winrm_sso")
                            result['auth_attempts'] = []  # Clear attempts on success
                            self.storage.update_host(ip, result)
                            return result
                        else:
                            logger.debug(f"WinRM SSO returned None for {ip}")
                            result['auth_attempts'].append({
                                'method': 'winrm_sso',
                                'status': 'failed'
                            })
                    except Exception as e:
                        logger.debug(f"WinRM SSO exception for {ip}: {e}")
                        result['auth_attempts'].append({
                            'method': 'winrm_sso',
                            'status': 'error',
                            'error': str(e)
                        })
            
            elif connector_type == 'ssh_key':
                # Try SSH keys
                if check_port_once(22, 'ssh'):
                    for cred in self.credential_manager:
                        if cred.get('type') == 'ssh':
                            user = cred.get('user')
                            key_paths = cred.get('key_paths', [])
                            
                            for key_path in key_paths:
                                info = self.ssh_connector.connect(ip, user, key_path=key_path)
                                if info:
                                    # Сохраняем существующий vendor из storage перед обновлением
                                    existing_host = self.storage.get_host(ip)
                                    existing_vendor = existing_host.get('vendor', '')
                                    if existing_vendor and not result.get('vendor'):
                                        result['vendor'] = existing_vendor
                                    
                                    result.update(info)
                                    
                                    # Если vendor все еще не установлен, пытаемся получить из MAC
                                    # Используем MAC из os_info, если доступен, иначе из result
                                    mac_for_vendor = None
                                    if info.get('os_info', {}).get('mac'):
                                        mac_for_vendor = info['os_info']['mac']
                                    elif result.get('mac'):
                                        mac_for_vendor = result.get('mac')
                                    
                                    if not result.get('vendor') and mac_for_vendor:
                                        vendor = self.fingerprinter.get_vendor_from_mac(mac_for_vendor)
                                        if vendor:
                                            result['vendor'] = vendor
                                    result['deep_scan_status'] = 'completed'
                                    result['auth_method'] = 'ssh_key'
                                    result['user'] = user
                                    logger.debug(f"{ip}: Successful authentication via ssh_key")
                                    result['auth_attempts'] = []  # Clear attempts on success
                                    self.storage.update_host(ip, result)
                                    return result
                                else:
                                    result['auth_attempts'].append({
                                        'method': 'ssh_key',
                                        'user': user,
                                        'status': 'failed'
                                    })
            
            elif connector_type == 'ssh':
                # Try SSH passwords
                if check_port_once(22, 'ssh'):
                    for cred in self.credential_manager:
                        if cred.get('type') == 'ssh':
                            user = cred.get('user')
                            passwords = cred.get('passwords', [])
                            
                            for password in passwords:
                                info = self.ssh_connector.connect(ip, user, password=password)
                                if info:
                                    # Сохраняем существующий vendor из storage перед обновлением
                                    existing_host = self.storage.get_host(ip)
                                    existing_vendor = existing_host.get('vendor', '')
                                    if existing_vendor and not result.get('vendor'):
                                        result['vendor'] = existing_vendor
                                    
                                    result.update(info)
                                    
                                    # Если vendor все еще не установлен, пытаемся получить из MAC
                                    # Используем MAC из os_info, если доступен, иначе из result
                                    mac_for_vendor = None
                                    if info.get('os_info', {}).get('mac'):
                                        mac_for_vendor = info['os_info']['mac']
                                    elif result.get('mac'):
                                        mac_for_vendor = result.get('mac')
                                    
                                    if not result.get('vendor') and mac_for_vendor:
                                        vendor = self.fingerprinter.get_vendor_from_mac(mac_for_vendor)
                                        if vendor:
                                            result['vendor'] = vendor
                                    result['deep_scan_status'] = 'completed'
                                    result['auth_method'] = 'ssh'
                                    result['user'] = user
                                    logger.debug(f"{ip}: Successful authentication via ssh")
                                    result['auth_attempts'] = []  # Clear attempts on success
                                    self.storage.update_host(ip, result)
                                    return result
                                else:
                                    result['auth_attempts'].append({
                                        'method': 'ssh',
                                        'user': user,
                                        'status': 'failed'
                                    })
            
            elif connector_type == 'winrm':
                # Try WinRM with credentials (only for Windows hosts)
                if not is_windows:
                    logger.debug(f"{ip}: Skipping WinRM - not a Windows host")
                    continue
                if check_port_once(5985, 'winrm'):
                    for cred in self.credential_manager:
                        if cred.get('type') == 'winrm':
                            user = cred.get('user')
                            passwords = cred.get('passwords', [])
                            
                            for password in passwords:
                                try:
                                    info = self.winrm_connector.connect(ip, user, password=password)
                                    if info:
                                        # Сохраняем существующий vendor из storage перед обновлением
                                        existing_host = self.storage.get_host(ip)
                                        existing_vendor = existing_host.get('vendor', '')
                                        if existing_vendor and not result.get('vendor'):
                                            result['vendor'] = existing_vendor
                                        
                                        result.update(info)
                                        
                                        # Если vendor все еще не установлен, пытаемся получить из MAC
                                        # Используем MAC из os_info, если доступен, иначе из result
                                        mac_for_vendor = None
                                        if info.get('os_info', {}).get('mac'):
                                            mac_for_vendor = info['os_info']['mac']
                                        elif result.get('mac'):
                                            mac_for_vendor = result.get('mac')
                                        
                                        if not result.get('vendor') and mac_for_vendor:
                                            vendor = self.fingerprinter.get_vendor_from_mac(mac_for_vendor)
                                            if vendor:
                                                result['vendor'] = vendor
                                        result['deep_scan_status'] = 'completed'
                                        result['auth_method'] = 'winrm'
                                        result['user'] = user
                                        logger.debug(f"{ip}: Successful authentication via winrm")
                                        result['auth_attempts'] = []  # Clear attempts on success
                                        self.storage.update_host(ip, result)
                                        return result
                                    else:
                                        result['auth_attempts'].append({
                                            'method': 'winrm',
                                            'user': user,
                                            'status': 'failed'
                                        })
                                except Exception as e:
                                    result['auth_attempts'].append({
                                        'method': 'winrm',
                                        'user': user,
                                        'status': 'error',
                                        'error': str(e)
                                    })
            
            elif connector_type == 'psexec':
                # Try PsExec with credentials from config (Windows only)
                if not is_windows:
                    logger.debug(f"{ip}: Skipping PSExec - not a Windows host")
                    continue
                if check_port_once(445, 'psexec'):
                    for cred in self.credential_manager:
                        if cred.get('type') == 'winrm':  # Use WinRM credentials for PsExec
                            user = cred.get('user')
                            passwords = cred.get('passwords', [])
                            
                            for password in passwords:
                                try:
                                    logger.debug(f"Trying PsExec with {user} for {ip}...")
                                    info = self.psexec_connector.connect(ip, user, password)
                                    if info:
                                        # Сохраняем существующий vendor из storage перед обновлением
                                        existing_host = self.storage.get_host(ip)
                                        existing_vendor = existing_host.get('vendor', '')
                                        if existing_vendor and not result.get('vendor'):
                                            result['vendor'] = existing_vendor
                                        
                                        result.update(info)
                                        
                                        # Если vendor все еще не установлен, пытаемся получить из MAC
                                        # PsExec не возвращает MAC, используем из result
                                        if not result.get('vendor') and result.get('mac'):
                                            vendor = self.fingerprinter.get_vendor_from_mac(result.get('mac'))
                                            if vendor:
                                                result['vendor'] = vendor
                                        result['deep_scan_status'] = 'completed'
                                        result['auth_method'] = 'psexec'
                                        result['user'] = user
                                        logger.debug(f"{ip}: Successful authentication via psexec")
                                        result['auth_attempts'] = []  # Clear attempts on success
                                        self.storage.update_host(ip, result)
                                        return result
                                    else:
                                        logger.debug(f"PsExec with {user} returned None for {ip}")
                                        result['auth_attempts'].append({
                                            'method': 'psexec',
                                            'user': user,
                                            'status': 'failed',
                                        })
                                except Exception as e:
                                    logger.debug(f"PsExec exception for {ip} with {user}: {e}")
                                    result['auth_attempts'].append({
                                        'method': 'psexec',
                                        'user': user,
                                        'status': 'error',
                                        'error': str(e)
                                    })

        # If auth failed, try fingerprinting
        if result['deep_scan_status'] != 'completed':
            fingerprint = self.fingerprinter.lightweight_fingerprint(
                ip,
                vendor=host_info.get('vendor'),
                mac=host_info.get('mac')
            )
            result.update(fingerprint)
            result['deep_scan_status'] = 'scanned_no_access'


        self.storage.update_host(ip, result)
        return result

    def scan_all(self, hosts, concurrency=20, force=False):
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(self.scan_host, host, force) for host in hosts]
            concurrent.futures.wait(futures)
