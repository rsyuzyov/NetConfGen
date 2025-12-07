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
    def connect(self, ip, user=None, password=None, key_path=None):
        if user and password:
            return self._connect_auth(ip, user, password)
        else:
            return self._connect_sso(ip)

    def _connect_auth(self, ip, user, password):
        try:
            session = winrm.Session(f'http://{ip}:5985/wsman', auth=(user, password), transport='ntlm')
            
            # Collect detailed OS information
            os_info = {}
            
            try:
                # Получаем название ОС
                result = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Caption')
                if result.status_code == 0:
                    os_info['os'] = result.std_out.decode().strip()
                
                # Получаем версию ОС
                result = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Version')
                if result.status_code == 0:
                    os_info['os_version'] = result.std_out.decode().strip()
                
                # Получаем hostname
                result = session.run_cmd('hostname')
                if result.status_code == 0:
                    os_info['hostname'] = result.std_out.decode().strip()
                
                # Получаем MAC адрес основного сетевого адаптера
                result = session.run_ps('(Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1).MacAddress')
                if result.status_code == 0:
                    mac = result.std_out.decode().strip()
                    if mac:
                        os_info['mac'] = mac.replace('-', ':')  # Конвертируем формат Windows в стандартный
                
                # Альтернативный способ для старых систем без Get-NetAdapter
                if 'mac' not in os_info:
                    result = session.run_cmd('getmac /v /fo csv | findstr /V "disabled"')
                    if result.status_code == 0:
                        output = result.std_out.decode().strip()
                        # Парсим первый MAC из вывода
                        import re
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                        if mac_match:
                            os_info['mac'] = mac_match.group(0).replace('-', ':')
                
                logger.debug(f"WinRM OS info collected for {ip}: {os_info}")
                
            except Exception as e:
                logger.debug(f"Failed to collect OS info via WinRM for {ip}: {e}")
                # Продолжаем без детальной информации
            
            # Формируем результат с обратной совместимостью
            result = {
                'success': True,
                'method': 'winrm',
                'hostname': os_info.get('hostname', ''),
                'os': os_info.get('os', 'Windows'),
                'type': 'windows',
                'user': user,
                'os_info': os_info
            }
            
            return result
        except:
            return None
        return None

    def _connect_sso(self, ip):
        current_user = os.environ.get('USERNAME', getpass.getuser())
        
        # Try different transports that support SSO
        if sys.platform == 'win32':
            transports_to_try = ['credssp', 'kerberos']
        else:
            transports_to_try = ['kerberos']
        
        for transport in transports_to_try:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    
                    session = winrm.Session(
                        f'http://{ip}:5985/wsman', 
                        auth=(None, None), 
                        transport=transport
                    )
                    
                    # Collect detailed OS information
                    os_info = {}
                    
                    try:
                        # Получаем название ОС
                        result = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Caption')
                        if result.status_code == 0:
                            os_info['os'] = result.std_out.decode().strip()
                        
                        # Получаем версию ОС
                        result = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Version')
                        if result.status_code == 0:
                            os_info['os_version'] = result.std_out.decode().strip()
                        
                        # Получаем hostname
                        result = session.run_cmd('hostname')
                        if result.status_code == 0:
                            os_info['hostname'] = result.std_out.decode().strip()
                        
                        # Получаем MAC адрес основного сетевого адаптера
                        result = session.run_ps('(Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1).MacAddress')
                        if result.status_code == 0:
                            mac = result.std_out.decode().strip()
                            if mac:
                                os_info['mac'] = mac.replace('-', ':')  # Конвертируем формат Windows в стандартный
                        
                        # Альтернативный способ для старых систем без Get-NetAdapter
                        if 'mac' not in os_info:
                            result = session.run_cmd('getmac /v /fo csv | findstr /V "disabled"')
                            if result.status_code == 0:
                                output = result.std_out.decode().strip()
                                # Парсим первый MAC из вывода
                                import re
                                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                                if mac_match:
                                    os_info['mac'] = mac_match.group(0).replace('-', ':')
                        
                        logger.debug(f"WinRM OS info collected for {ip} (SSO): {os_info}")
                        
                    except Exception as e:
                        logger.debug(f"Failed to collect OS info via WinRM for {ip} (SSO): {e}")
                        # Продолжаем без детальной информации
                    
                    # Формируем результат с обратной совместимостью
                    return {
                        'success': True,
                        'method': 'winrm',
                        'hostname': os_info.get('hostname', ''),
                        'os': os_info.get('os', 'Windows'),
                        'type': 'windows',
                        'user': current_user,
                        'auth_method': 'winrm_sso',
                        'os_info': os_info
                    }
            except Exception:
                continue  # Try next transport
        
        return None
