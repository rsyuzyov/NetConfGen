import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from .credentials import CredentialManager

logger = logging.getLogger(__name__)

class ConnectionChecker:
    def __init__(self, credentials, storage):
        self.storage = storage
        
        # Helper modules
        self.credential_manager = CredentialManager(credentials)
        
        # Connectors - отложенная инициализация
        self._ssh_connector = None
        self._winrm_connector = None
        self._psexec_connector = None
    
    @property
    def ssh_connector(self):
        if self._ssh_connector is None:
            from .connectors.ssh import SSHConnector
            self._ssh_connector = SSHConnector()
        return self._ssh_connector
    
    @property
    def winrm_connector(self):
        if self._winrm_connector is None:
            from .connectors.winrm import WinRMConnector
            self._winrm_connector = WinRMConnector()
        return self._winrm_connector
    
    @property
    def psexec_connector(self):
        if self._psexec_connector is None:
            from .connectors.psexec import PsExecConnector
            self._psexec_connector = PsExecConnector()
        return self._psexec_connector
    
    def _has_required_ports(self, host_info):
        """
        Проверяет, есть ли у хоста открытые порты для SSH, WinRM или PSExec.
        
        Args:
            host_info: информация о хосте из storage
            
        Returns:
            bool: True если есть нужные порты
        """
        open_ports = host_info.get('open_ports', [])
        if not open_ports:
            return False
        
        # Порты для подключения
        ssh_port = 22
        winrm_port = 5985
        smb_port = 445  # для PSExec
        
        return ssh_port in open_ports or winrm_port in open_ports or smb_port in open_ports

    def check_host_connection(self, ip, force=False):
        """
        Проверяет подключение к хосту.
        
        Args:
            ip: IP адрес хоста
            force: принудительная проверка (игнорировать кэш)
            
        Returns:
            dict: результат проверки подключения
        """
        # Получаем информацию о хосте из storage
        host_info = self.storage.get_host(ip)
        
        if not host_info:
            logger.warning(f"{ip}: Хост не найден в storage")
            return None
        
        # Проверяем наличие нужных портов
        if not self._has_required_ports(host_info):
            logger.info(f"{ip}: Нет открытых портов для подключения (SSH:22, WinRM:5985, SMB:445)")
            return None
        
        # Проверяем кэш
        if not force and self.storage.is_scanned(ip):
            logger.debug(f"{ip}: Уже проверен (используем кэш)")
            return self.storage.get_host(ip)
        
        logger.info(f"Проверка подключения к {ip}...")
        
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
        
        open_ports = host_info.get('open_ports', [])
        
        # Определяем тип хоста по открытым портам
        is_windows = 445 in open_ports or 5985 in open_ports or 3389 in open_ports
        is_linux = 22 in open_ports
        is_mikrotik = 8291 in open_ports or 8728 in open_ports
        
        # Также проверяем сохраненный тип хоста
        if not is_windows and host_info.get('type') == 'windows':
            is_windows = True
        
        logger.debug(f"{ip}: Windows={is_windows}, Linux={is_linux}, MikroTik={is_mikrotik}")
        
        # Если обнаружен MikroTik
        if is_mikrotik:
            result['os'] = 'RouterOS'
            result['type'] = 'network'
            result['device_type'] = 'mikrotik'
            logger.debug(f"{ip}: Определен как MikroTik")
        
        # Приоритизация коннекторов
        auth_attempts = []
        
        # Если есть SSH порт - всегда пробуем SSH первым (быстрее и надежнее)
        if is_linux:
            auth_attempts.extend(['ssh_key', 'ssh'])
        
        # Если есть признаки Windows - добавляем Windows методы
        if is_windows:
            auth_attempts.extend(['winrm_sso', 'winrm', 'psexec'])
        
        # Если ничего не определено, но есть SSH порт - пробуем SSH
        if not auth_attempts and 22 in open_ports:
            auth_attempts.extend(['ssh'])

        # Перебор коннекторов с приоритизацией
        for connector_type in auth_attempts:
            if connector_type == 'winrm_sso':
                # WinRM SSO (только для Windows)
                if not is_windows:
                    logger.debug(f"{ip}: Пропускаем WinRM SSO - не Windows хост")
                    continue
                if 5985 not in open_ports:
                    result['auth_attempts'].append({
                        'method': 'winrm_sso',
                        'status': 'skipped',
                        'error': 'Порт 5985 закрыт'
                    })
                    continue
                
                try:
                    logger.debug(f"Пробуем WinRM SSO для {ip}...")
                    info = self.winrm_connector.connect(ip, user=None, password=None)
                    if info:
                        existing_host = self.storage.get_host(ip)
                        existing_vendor = existing_host.get('vendor', '')
                        if existing_vendor and not result.get('vendor'):
                            result['vendor'] = existing_vendor
                        
                        result.update(info)
                        
                        result['deep_scan_status'] = 'completed'
                        result['auth_method'] = 'winrm_sso'
                        logger.info(f"{ip}: Успешное подключение через winrm_sso")
                        result['auth_attempts'] = []
                        self.storage.update_host(ip, result)
                        return result
                    else:
                        logger.debug(f"WinRM SSO вернул None для {ip}")
                        result['auth_attempts'].append({
                            'method': 'winrm_sso',
                            'status': 'failed'
                        })
                except Exception as e:
                    logger.debug(f"Ошибка WinRM SSO для {ip}: {e}")
                    result['auth_attempts'].append({
                        'method': 'winrm_sso',
                        'status': 'error',
                        'error': str(e)
                    })
            
            elif connector_type == 'ssh_key':
                # SSH с ключами
                if 22 not in open_ports:
                    result['auth_attempts'].append({
                        'method': 'ssh_key',
                        'status': 'skipped',
                        'error': 'Порт 22 закрыт'
                    })
                    continue
                
                for cred in self.credential_manager:
                    if cred.get('type') == 'ssh':
                        user = cred.get('user')
                        key_paths = cred.get('key_paths', [])
                        
                        for key_path in key_paths:
                            info = self.ssh_connector.connect(ip, user, key_path=key_path)
                            if info:
                                existing_host = self.storage.get_host(ip)
                                existing_vendor = existing_host.get('vendor', '')
                                if existing_vendor and not result.get('vendor'):
                                    result['vendor'] = existing_vendor
                                
                                result.update(info)
                                
                                result['deep_scan_status'] = 'completed'
                                result['auth_method'] = 'ssh_key'
                                result['user'] = user
                                logger.info(f"{ip}: Успешное подключение через ssh_key")
                                result['auth_attempts'] = []
                                self.storage.update_host(ip, result)
                                return result
                            else:
                                result['auth_attempts'].append({
                                    'method': 'ssh_key',
                                    'user': user,
                                    'status': 'failed'
                                })

            elif connector_type == 'ssh':
                # SSH с паролями
                if 22 not in open_ports:
                    result['auth_attempts'].append({
                        'method': 'ssh',
                        'status': 'skipped',
                        'error': 'Порт 22 закрыт'
                    })
                    continue
                
                for cred in self.credential_manager:
                    if cred.get('type') == 'ssh':
                        user = cred.get('user')
                        passwords = cred.get('passwords', [])
                        
                        for password in passwords:
                            info = self.ssh_connector.connect(ip, user, password=password)
                            if info:
                                existing_host = self.storage.get_host(ip)
                                existing_vendor = existing_host.get('vendor', '')
                                if existing_vendor and not result.get('vendor'):
                                    result['vendor'] = existing_vendor
                                
                                result.update(info)
                                
                                result['deep_scan_status'] = 'completed'
                                result['auth_method'] = 'ssh'
                                result['user'] = user
                                logger.info(f"{ip}: Успешное подключение через ssh")
                                result['auth_attempts'] = []
                                self.storage.update_host(ip, result)
                                return result
                            else:
                                result['auth_attempts'].append({
                                    'method': 'ssh',
                                    'user': user,
                                    'status': 'failed'
                                })
            
            elif connector_type == 'winrm':
                # WinRM с учетными данными (только для Windows)
                if not is_windows:
                    logger.debug(f"{ip}: Пропускаем WinRM - не Windows хост")
                    continue
                if 5985 not in open_ports:
                    result['auth_attempts'].append({
                        'method': 'winrm',
                        'status': 'skipped',
                        'error': 'Порт 5985 закрыт'
                    })
                    continue
                
                for cred in self.credential_manager:
                    if cred.get('type') == 'winrm':
                        user = cred.get('user')
                        passwords = cred.get('passwords', [])
                        
                        for password in passwords:
                            try:
                                info = self.winrm_connector.connect(ip, user, password=password)
                                if info:
                                    existing_host = self.storage.get_host(ip)
                                    existing_vendor = existing_host.get('vendor', '')
                                    if existing_vendor and not result.get('vendor'):
                                        result['vendor'] = existing_vendor
                                    
                                    result.update(info)
                                    
                                    result['deep_scan_status'] = 'completed'
                                    result['auth_method'] = 'winrm'
                                    result['user'] = user
                                    logger.info(f"{ip}: Успешное подключение через winrm")
                                    result['auth_attempts'] = []
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
                # PsExec (только для Windows)
                if not is_windows:
                    logger.debug(f"{ip}: Пропускаем PSExec - не Windows хост")
                    continue
                if 445 not in open_ports:
                    result['auth_attempts'].append({
                        'method': 'psexec',
                        'status': 'skipped',
                        'error': 'Порт 445 закрыт'
                    })
                    continue
                
                for cred in self.credential_manager:
                    if cred.get('type') == 'winrm':  # Используем WinRM credentials для PsExec
                        user = cred.get('user')
                        passwords = cred.get('passwords', [])
                        
                        logger.debug(f"Найдены credentials для PsExec: user={user}, passwords count={len(passwords)}")
                        
                        for password in passwords:
                            try:
                                logger.debug(f"Пробуем PsExec с {user} для {ip} (password length: {len(password)})...")
                                info = self.psexec_connector.connect(ip, user, password)
                                if info:
                                    existing_host = self.storage.get_host(ip)
                                    existing_vendor = existing_host.get('vendor', '')
                                    if existing_vendor and not result.get('vendor'):
                                        result['vendor'] = existing_vendor
                                    
                                    result.update(info)
                                    
                                    result['deep_scan_status'] = 'completed'
                                    result['auth_method'] = 'psexec'
                                    result['user'] = user
                                    logger.info(f"{ip}: Успешное подключение через psexec")
                                    result['auth_attempts'] = []
                                    self.storage.update_host(ip, result)
                                    return result
                                else:
                                    logger.debug(f"PsExec с {user} вернул None для {ip}")
                                    result['auth_attempts'].append({
                                        'method': 'psexec',
                                        'user': user,
                                        'status': 'failed',
                                    })
                            except Exception as e:
                                logger.debug(f"Ошибка PsExec для {ip} с {user}: {e}")
                                result['auth_attempts'].append({
                                    'method': 'psexec',
                                    'user': user,
                                    'status': 'error',
                                    'error': str(e)
                                })
        
        # Если аутентификация не удалась
        if result['deep_scan_status'] != 'completed':
            result['deep_scan_status'] = 'scanned_no_access'
        
        self.storage.update_host(ip, result)
        return result
    
    def check_all_hosts(self, hosts=None, concurrency=20, force=False):
        """
        Проверяет подключение ко всем хостам.
        
        Args:
            hosts: список IP адресов или None для всех хостов из storage
            concurrency: количество одновременных проверок
            force: принудительная проверка (игнорировать кэш)
            
        Returns:
            list: список результатов проверки
        """
        # Если hosts не указан, берем все хосты из storage с нужными портами
        if hosts is None:
            all_hosts = self.storage.data
            hosts = []
            for ip, host_info in all_hosts.items():
                if self._has_required_ports(host_info):
                    hosts.append(ip)
            logger.info(f"Проверка всех хостов с открытыми портами SSH/WinRM/SMB: {len(hosts)} хостов")
        else:
            logger.info(f"Проверка указанных хостов: {len(hosts)} хостов")
        
        if not hosts:
            logger.warning("Нет хостов для проверки подключения")
            return []
        
        results = []
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(self.check_host_connection, ip, force): ip for ip in hosts}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    ip = futures[future]
                    logger.error(f"Ошибка при проверке подключения к {ip}: {e}")
        
        logger.info(f"Проверка подключения завершена: {len(results)} хостов")
        return results
