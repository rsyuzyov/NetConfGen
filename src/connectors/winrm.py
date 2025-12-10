import winrm
import warnings
import logging
import getpass
import os
import sys
from . import BaseConnector

logger = logging.getLogger(__name__)

# Suppress noisy errors from the library
logging.getLogger('winrm').setLevel(logging.CRITICAL)
logging.getLogger('requests_kerberos').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)

class WinRMConnector(BaseConnector):
    # Подменяем kerberos-авторизацию на GSSAPI (wheels для 3.13)
    _kerberos_patched = False

    @classmethod
    def _ensure_gssapi_auth(cls):
        if cls._kerberos_patched:
            return
        try:
            from requests.auth import AuthBase
            from requests_gssapi import HTTPSPNEGOAuth
            import winrm.transport as wt
            # Повторно используем константу REQUIRED из vendored requests_kerberos
            REQUIRED = getattr(wt, "REQUIRED", 1)

            class GSSAPIKerberosAuth(AuthBase):
                # Шифрование WinRM через SPNEGO не поддерживаем, поэтому False
                winrm_encryption_available = False

                def __init__(self, mutual_authentication=REQUIRED, service="HTTP", delegate=False,
                             force_preemptive=False, principal=None, hostname_override=None,
                             sanitize_mutual_error_response=True, send_cbt=True):
                    # HTTPSPNEGOAuth ожидает host/service, делегирование и principal
                    self._auth = HTTPSPNEGOAuth(
                        principal=principal,
                        hostname_override=hostname_override,
                        delegate=delegate,
                        opportunistic_auth=force_preemptive,
                        service=service,
                        mutual_authentication=True if mutual_authentication == REQUIRED else False,
                    )

                def __call__(self, r):
                    return self._auth(r)

            wt.HTTPKerberosAuth = GSSAPIKerberosAuth
            wt.HAVE_KERBEROS = True
            cls._kerberos_patched = True
        except Exception:
            # Оставляем поведение по умолчанию, если gssapi не установлена
            pass

    def connect(self, ip, user=None, password=None, key_path=None):
        # key_path не используется в WinRM (только логин/пароль или SSO)
        self._ensure_gssapi_auth()
        
        # Определяем режим аутентификации
        if user and password:
            # Аутентификация с логином/паролем
            auth_mode = 'ntlm'
            session = winrm.Session(f'http://{ip}:5985/wsman', auth=(user, password), transport='ntlm')
            log_prefix = 'AUTH'
        else:
            # SSO аутентификация
            current_user = os.environ.get('USERNAME', getpass.getuser())
            user = current_user
            auth_mode = 'sso'
            log_prefix = 'SSO'
            
            # Определяем транспорты для SSO
            if sys.platform == 'win32':
                transports_to_try = ['credssp', 'kerberos']
            else:
                transports_to_try = ['kerberos']
        
        # Для SSO пробуем разные транспорты
        if auth_mode == 'sso':
            for transport in transports_to_try:
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        session = winrm.Session(f'http://{ip}:5985/wsman', auth=(None, None), transport=transport)
                        
                        # Пробуем получить информацию
                        os_info = self._collect_os_info(ip, session, log_prefix)
                        
                        if os_info is None:
                            # Не удалось получить данные, пробуем следующий транспорт
                            if transport == transports_to_try[-1]:
                                return {'error': 'Failed to execute commands with all transports'}
                            continue
                        
                        # Успешно получили данные
                        logger.info(f"[{ip}] {log_prefix}: Successfully connected with transport {transport}")
                        return {
                            'success': True,
                            'method': 'winrm',
                            'hostname': os_info.get('hostname', ''),
                            'os': os_info.get('os', 'Windows'),
                            'os_type': 'windows',
                            'type': 'workstation',
                            'user': user,
                            'auth_method': 'winrm_sso',
                            'mac': os_info.get('mac', ''),
                            'kernel_version': os_info.get('kernel_version', '')
                        }
                except Exception as e:
                    error_str = str(e).lower()
                    if any(keyword in error_str for keyword in ['401', 'unauthorized', 'authentication', 'credentials', 'logon failure']):
                        logger.debug(f"WinRM SSO authentication failed for {ip} with transport {transport}: {e}")
                        if transport == transports_to_try[-1]:
                            return {'auth_failed': True, 'error': f'Authentication failed: {str(e)}'}
                    if transport == transports_to_try[-1]:
                        return {'error': f'Connection error with all transports. Last error: {str(e)}'}
                    continue
            
            return {'error': 'All transports failed without specific error'}
        
        # Для NTLM аутентификации
        try:
            os_info = self._collect_os_info(ip, session, log_prefix)
            
            if os_info is None:
                return {'error': 'Failed to execute commands'}
            
            logger.info(f"[{ip}] {log_prefix}: Successfully authenticated with user {user}")
            return {
                'success': True,
                'method': 'winrm',
                'hostname': os_info.get('hostname', ''),
                'os': os_info.get('os', 'Windows'),
                'os_type': 'windows',
                'type': 'workstation',
                'user': user,
                'mac': os_info.get('mac', ''),
                'kernel_version': os_info.get('kernel_version', '')
            }
        except Exception as e:
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ['401', 'unauthorized', 'authentication', 'credentials', 'logon failure']):
                logger.debug(f"WinRM authentication failed for {ip}: {e}")
                return {'auth_failed': True, 'error': f'Authentication failed: {str(e)}'}
            logger.debug(f"WinRM connection failed for {ip}: {e}")
            return {'error': f'Connection error: {str(e)}'}
    
    def _collect_os_info(self, ip, session, log_prefix):
        """Собирает информацию об ОС. Возвращает dict с данными или None при ошибке."""
        os_info = {}
        
        try:
            # Получаем название ОС
            logger.debug(f"[{ip}] {log_prefix}: Executing OS Caption query...")
            result = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Caption')
            logger.debug(f"[{ip}] {log_prefix}: OS Caption - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
            if result.status_code == 0:
                os_info['os'] = result.std_out.decode().strip()
                logger.debug(f"[{ip}] {log_prefix}: OS Caption result: '{os_info['os']}'")
            else:
                logger.debug(f"[{ip}] {log_prefix}: OS Caption failed, stderr: {result.std_err.decode()}")
            
            # Получаем версию ОС
            logger.debug(f"[{ip}] {log_prefix}: Executing OS Version query...")
            result = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Version')
            logger.debug(f"[{ip}] {log_prefix}: OS Version - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
            if result.status_code == 0:
                os_info['kernel_version'] = result.std_out.decode().strip()
                logger.debug(f"[{ip}] {log_prefix}: OS Version result: '{os_info['kernel_version']}'")
            else:
                logger.debug(f"[{ip}] {log_prefix}: OS Version failed, stderr: {result.std_err.decode()}")
            
            # Получаем hostname
            logger.debug(f"[{ip}] {log_prefix}: Executing hostname command...")
            result = session.run_cmd('hostname')
            logger.debug(f"[{ip}] {log_prefix}: hostname - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
            logger.debug(f"[{ip}] {log_prefix}: hostname raw stdout: {result.std_out}")
            logger.debug(f"[{ip}] {log_prefix}: hostname raw stderr: {result.std_err}")
            if result.status_code == 0:
                os_info['hostname'] = result.std_out.decode().strip()
                logger.debug(f"[{ip}] {log_prefix}: hostname result: '{os_info['hostname']}'")
            else:
                logger.debug(f"[{ip}] {log_prefix}: hostname failed, stderr: {result.std_err.decode()}")
            
            # Получаем MAC адрес основного сетевого адаптера
            logger.debug(f"[{ip}] {log_prefix}: Executing MAC address query...")
            result = session.run_ps('(Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1).MacAddress')
            logger.debug(f"[{ip}] {log_prefix}: MAC query - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
            if result.status_code == 0:
                mac = result.std_out.decode().strip()
                if mac:
                    os_info['mac'] = mac.replace('-', ':')
                    logger.debug(f"[{ip}] {log_prefix}: MAC address result: '{os_info['mac']}'")
                else:
                    logger.debug(f"[{ip}] {log_prefix}: MAC address query returned empty")
            else:
                logger.debug(f"[{ip}] {log_prefix}: MAC query failed, stderr: {result.std_err.decode()}")
            
            # Альтернативный способ для старых систем без Get-NetAdapter
            if 'mac' not in os_info:
                logger.debug(f"[{ip}] {log_prefix}: Trying alternative MAC query with getmac...")
                result = session.run_cmd('getmac /v /fo csv | findstr /V "disabled"')
                logger.debug(f"[{ip}] {log_prefix}: getmac - status_code={result.status_code}, stdout_len={len(result.std_out)}")
                if result.status_code == 0:
                    output = result.std_out.decode().strip()
                    import re
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                    if mac_match:
                        os_info['mac'] = mac_match.group(0).replace('-', ':')
                        logger.debug(f"[{ip}] {log_prefix}: Alternative MAC result: '{os_info['mac']}'")
            
            logger.debug(f"[{ip}] {log_prefix}: WinRM OS info collected: {os_info}")
            
        except Exception as e:
            logger.debug(f"[{ip}] {log_prefix}: Failed to collect OS info via WinRM: {e}")
            return None
        
        # Проверяем что удалось получить хотя бы hostname
        if not os_info.get('hostname'):
            logger.debug(f"[{ip}] {log_prefix}: Connected but failed to get hostname")
            return None
        
        return os_info
