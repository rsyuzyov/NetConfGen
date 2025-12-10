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
            'os_type': 'linux',
            'type': 'unknown',
            'deep_scan_status': 'failed',
            'auth_methods': [],  # Список всех рабочих протоколов
            'auth_attempts': []  # Обязательное поле для всех попыток
        }
        
        open_ports = host_info.get('open_ports', [])
        
        # Определяем тип хоста по открытым портам (для информации)
        is_mikrotik = 8291 in open_ports or 8728 in open_ports
        
        logger.debug(f"{ip}: Open ports: {open_ports}")
        
        # Если обнаружен MikroTik
        if is_mikrotik:
            result['os'] = 'RouterOS'
            result['os_type'] = 'linux'
            result['type'] = 'mikrotik'
            result['device_type'] = 'mikrotik'
            logger.debug(f"{ip}: Определен как MikroTik")
        
        # Формируем список методов для проверки на основе открытых портов
        # ВАЖНО: проверяем все протоколы, если порт открыт, независимо от типа ОС
        auth_methods_to_try = []
        
        # SSH - если порт 22 открыт
        if 22 in open_ports:
            auth_methods_to_try.extend(['ssh_key', 'ssh'])
        
        # WinRM - если порт 5985 открыт
        if 5985 in open_ports:
            auth_methods_to_try.append('winrm')
        
        # PSExec - если порт 445 открыт
        if 445 in open_ports:
            auth_methods_to_try.append('psexec')
        
        logger.debug(f"{ip}: Methods to try based on open ports: {auth_methods_to_try}")

        # Перебор коннекторов
        # Флаг успешного подключения (для получения hostname и других данных)
        connection_successful = False
        
        for connector_type in auth_methods_to_try:
            if connector_type == 'ssh_key':
                # SSH с ключами
                for cred in self.credential_manager:
                    if cred.get('type') == 'ssh':
                        user = cred.get('user')
                        key_paths = cred.get('key_paths', [])
                        
                        for key_path in key_paths:
                            info = self.ssh_connector.connect(ip, user, key_path=key_path)
                            
                            if info and info.get('auth_failed'):
                                # Протокол работает, но аутентификация не прошла
                                logger.info(f"{ip}: SSH (key) - протокол работает, но аутентификация не прошла для {user}")
                                if 'ssh' not in result['auth_methods']:
                                    result['auth_methods'].append('ssh')
                                result['auth_attempts'].append({
                                    'method': 'ssh_key',
                                    'user': user,
                                    'status': 'auth_failed',
                                    'error': info.get('error', 'Authentication failed')
                                })
                            elif info:
                                # Успешное подключение
                                existing_host = self.storage.get_host(ip)
                                existing_vendor = existing_host.get('vendor', '')
                                if existing_vendor and not result.get('vendor'):
                                    result['vendor'] = existing_vendor
                                
                                # Обновляем данные только если еще не было успешного подключения
                                if not connection_successful:
                                    result.update(info)
                                    result['deep_scan_status'] = 'completed'
                                    connection_successful = True
                                
                                if 'ssh' not in result['auth_methods']:
                                    result['auth_methods'].append('ssh')
                                result['user'] = user
                                logger.info(f"{ip}: Успешное подключение через ssh_key")
                                result['auth_attempts'].append({
                                    'method': 'ssh_key',
                                    'user': user,
                                    'status': 'success'
                                })
                                # Продолжаем проверять другие протоколы
                            else:
                                result['auth_attempts'].append({
                                    'method': 'ssh_key',
                                    'user': user,
                                    'status': 'failed',
                                    'error': 'Connection failed'
                                })

            elif connector_type == 'ssh':
                # SSH с паролями
                for cred in self.credential_manager:
                    if cred.get('type') == 'ssh':
                        user = cred.get('user')
                        passwords = cred.get('passwords', [])
                        
                        for password in passwords:
                            info = self.ssh_connector.connect(ip, user, password=password)
                            
                            if info and info.get('auth_failed'):
                                # Протокол работает, но аутентификация не прошла
                                logger.info(f"{ip}: SSH (password) - протокол работает, но аутентификация не прошла для {user}")
                                if 'ssh' not in result['auth_methods']:
                                    result['auth_methods'].append('ssh')
                                result['auth_attempts'].append({
                                    'method': 'ssh',
                                    'user': user,
                                    'status': 'auth_failed',
                                    'error': info.get('error', 'Authentication failed')
                                })
                            elif info:
                                # Успешное подключение
                                existing_host = self.storage.get_host(ip)
                                existing_vendor = existing_host.get('vendor', '')
                                if existing_vendor and not result.get('vendor'):
                                    result['vendor'] = existing_vendor
                                
                                # Обновляем данные только если еще не было успешного подключения
                                if not connection_successful:
                                    result.update(info)
                                    result['deep_scan_status'] = 'completed'
                                    connection_successful = True
                                
                                if 'ssh' not in result['auth_methods']:
                                    result['auth_methods'].append('ssh')
                                result['user'] = user
                                logger.info(f"{ip}: Успешное подключение через ssh")
                                result['auth_attempts'].append({
                                    'method': 'ssh',
                                    'user': user,
                                    'status': 'success'
                                })
                                # Продолжаем проверять другие протоколы
                            else:
                                result['auth_attempts'].append({
                                    'method': 'ssh',
                                    'user': user,
                                    'status': 'failed',
                                    'error': 'Connection failed'
                                })
            
            elif connector_type == 'winrm':
                # Сначала пробуем SSO
                try:
                    logger.debug(f"Пробуем WinRM SSO для {ip}...")
                    info = self.winrm_connector.connect(ip, user=None, password=None)
                    
                    if info and info.get('auth_failed'):
                        # Протокол работает, но аутентификация не прошла
                        logger.info(f"{ip}: WinRM SSO - протокол работает, но аутентификация не прошла")
                        if 'winrm' not in result['auth_methods']:
                            result['auth_methods'].append('winrm')
                        result['auth_attempts'].append({
                            'method': 'winrm',
                            'user': info.get('user', ''),
                            'status': 'auth_failed',
                            'error': info.get('error', 'Authentication failed')
                        })
                    elif info:
                        # Успешное подключение через SSO
                        existing_host = self.storage.get_host(ip)
                        existing_vendor = existing_host.get('vendor', '')
                        if existing_vendor and not result.get('vendor'):
                            result['vendor'] = existing_vendor
                        
                        result.update(info)
                        if 'winrm' not in result['auth_methods']:
                            result['auth_methods'].append('winrm')
                        result['deep_scan_status'] = 'completed'
                        connection_successful = True
                        sso_user = info.get('user', '')
                        logger.info(f"{ip}: Успешное подключение через winrm (SSO) user={sso_user}")
                        result['auth_attempts'].append({
                            'method': 'winrm',
                            'user': sso_user,
                            'status': 'success'
                        })
                        # Продолжаем проверять другие протоколы
                    else:
                        logger.debug(f"WinRM SSO вернул None для {ip}")
                        result['auth_attempts'].append({
                            'method': 'winrm',
                            'status': 'failed',
                            'error': 'Connection failed'
                        })
                except Exception as e:
                    logger.debug(f"Ошибка WinRM SSO для {ip}: {e}")
                    result['auth_attempts'].append({
                        'method': 'winrm',
                        'status': 'error',
                        'error': str(e)
                    })
                
                # Затем пробуем с учетными данными
                for cred in self.credential_manager:
                    if cred.get('type') == 'winrm':
                        user = cred.get('user')
                        passwords = cred.get('passwords', [])
                        
                        for password in passwords:
                            try:
                                info = self.winrm_connector.connect(ip, user, password=password)
                                
                                if info and info.get('auth_failed'):
                                    # Протокол работает, но аутентификация не прошла
                                    logger.info(f"{ip}: WinRM - протокол работает, но аутентификация не прошла для {user}")
                                    if 'winrm' not in result['auth_methods']:
                                        result['auth_methods'].append('winrm')
                                    result['auth_attempts'].append({
                                        'method': 'winrm',
                                        'user': user,
                                        'status': 'auth_failed',
                                        'error': info.get('error', 'Authentication failed')
                                    })
                                elif info:
                                    # Успешное подключение
                                    existing_host = self.storage.get_host(ip)
                                    existing_vendor = existing_host.get('vendor', '')
                                    if existing_vendor and not result.get('vendor'):
                                        result['vendor'] = existing_vendor
                                    
                                    # Обновляем данные только если еще не было успешного подключения
                                    if not connection_successful:
                                        result.update(info)
                                        result['deep_scan_status'] = 'completed'
                                        connection_successful = True
                                    
                                    if 'winrm' not in result['auth_methods']:
                                        result['auth_methods'].append('winrm')
                                    result['user'] = user
                                    logger.info(f"{ip}: Успешное подключение через winrm")
                                    result['auth_attempts'].append({
                                        'method': 'winrm',
                                        'user': user,
                                        'status': 'success'
                                    })
                                    # Продолжаем проверять другие протоколы
                                else:
                                    result['auth_attempts'].append({
                                        'method': 'winrm',
                                        'user': user,
                                        'status': 'failed',
                                        'error': 'Connection failed'
                                    })
                            except Exception as e:
                                result['auth_attempts'].append({
                                    'method': 'winrm',
                                    'user': user,
                                    'status': 'error',
                                    'error': str(e)
                                })

            elif connector_type == 'psexec':
                # PsExec
                for cred in self.credential_manager:
                    if cred.get('type') == 'winrm':  # Используем WinRM credentials для PsExec
                        user = cred.get('user')
                        passwords = cred.get('passwords', [])
                        
                        logger.debug(f"Найдены credentials для PsExec: user={user}, passwords count={len(passwords)}")
                        
                        for password in passwords:
                            try:
                                logger.debug(f"Пробуем PsExec с {user} для {ip} (password length: {len(password)})...")
                                info = self.psexec_connector.connect(ip, user, password)
                                
                                if info and info.get('auth_failed'):
                                    # Протокол работает, но аутентификация не прошла
                                    logger.info(f"{ip}: PSExec - протокол работает, но аутентификация не прошла для {user}")
                                    if 'psexec' not in result['auth_methods']:
                                        result['auth_methods'].append('psexec')
                                    result['auth_attempts'].append({
                                        'method': 'psexec',
                                        'user': user,
                                        'status': 'auth_failed',
                                        'error': info.get('error', 'Authentication failed')
                                    })
                                elif info:
                                    # Успешное подключение
                                    existing_host = self.storage.get_host(ip)
                                    existing_vendor = existing_host.get('vendor', '')
                                    if existing_vendor and not result.get('vendor'):
                                        result['vendor'] = existing_vendor
                                    
                                    # Обновляем данные только если еще не было успешного подключения
                                    if not connection_successful:
                                        result.update(info)
                                        result['deep_scan_status'] = 'completed'
                                        connection_successful = True
                                    
                                    if 'psexec' not in result['auth_methods']:
                                        result['auth_methods'].append('psexec')
                                    result['user'] = user
                                    logger.info(f"{ip}: Успешное подключение через psexec")
                                    result['auth_attempts'].append({
                                        'method': 'psexec',
                                        'user': user,
                                        'status': 'success'
                                    })
                                    # Продолжаем проверять другие протоколы
                                else:
                                    logger.debug(f"PsExec с {user} вернул None для {ip}")
                                    result['auth_attempts'].append({
                                        'method': 'psexec',
                                        'user': user,
                                        'status': 'failed',
                                        'error': 'Connection failed'
                                    })
                            except Exception as e:
                                logger.debug(f"Ошибка PsExec для {ip} с {user}: {e}")
                                result['auth_attempts'].append({
                                    'method': 'psexec',
                                    'user': user,
                                    'status': 'error',
                                    'error': str(e)
                                })
        
        # Определяем финальный статус
        if connection_successful:
            result['deep_scan_status'] = 'completed'
        elif result['auth_methods']:
            # Есть рабочие протоколы, но подключиться не удалось
            result['deep_scan_status'] = 'auth_available_no_access'
        else:
            # Ни один протокол не ответил корректно
            result['deep_scan_status'] = 'scanned_no_access'
        
        self.storage.update_host(ip, result)
        logger.info(f"{ip}: Проверка завершена. Статус: {result['deep_scan_status']}, "
                   f"Рабочие протоколы: {result['auth_methods']}, "
                   f"Попыток подключения: {len(result['auth_attempts'])}")
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
