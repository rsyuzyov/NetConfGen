import paramiko
import logging
from . import BaseConnector

logger = logging.getLogger(__name__)

class SSHConnector(BaseConnector):
    def connect(self, ip, user, password=None, key_path=None):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # Connect with password or key
            if key_path:
                client.connect(ip, username=user, key_filename=key_path, timeout=5)
            elif password:
                client.connect(ip, username=user, password=password, timeout=5)
            else:
                return None
            
            # Collect detailed OS information
            os_info = {}
            
            try:
                # Получаем тип ОС
                stdin, stdout, stderr = client.exec_command('uname -s', timeout=5)
                os_type = stdout.read().decode().strip()
                if os_type:
                    os_info['os'] = os_type
                
                # Получаем версию ядра
                stdin, stdout, stderr = client.exec_command('uname -r', timeout=5)
                os_version = stdout.read().decode().strip()
                if os_version:
                    os_info['os_version'] = os_version
                
                # Получаем hostname
                stdin, stdout, stderr = client.exec_command('hostname', timeout=5)
                hostname = stdout.read().decode().strip()
                if hostname:
                    os_info['hostname'] = hostname
                
                # Получаем дистрибутив (может не сработать на всех системах)
                stdin, stdout, stderr = client.exec_command('cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d \'"\'', timeout=5)
                distribution = stdout.read().decode().strip()
                if distribution:
                    os_info['distribution'] = distribution
                
                # Получаем первый MAC адрес
                stdin, stdout, stderr = client.exec_command('ip link show 2>/dev/null | grep ether | head -n1 | awk \'{print $2}\'', timeout=5)
                mac = stdout.read().decode().strip()
                if not mac:
                    # Fallback для систем без ip команды
                    stdin, stdout, stderr = client.exec_command('ifconfig 2>/dev/null | grep ether | head -n1 | awk \'{print $2}\'', timeout=5)
                    mac = stdout.read().decode().strip()
                if mac:
                    os_info['mac'] = mac
                    
                logger.debug(f"SSH OS info collected for {ip}: {os_info}")
                
            except Exception as e:
                logger.debug(f"Failed to collect OS info via SSH for {ip}: {e}")
                # Продолжаем без детальной информации
            
            client.close()
            
            # Формируем результат с обратной совместимостью
            # ВАЖНО: НЕ сохраняем key_path для безопасности
            result = {
                'success': True,
                'method': 'ssh',
                'hostname': os_info.get('hostname', ''),
                'os': os_info.get('distribution', os_info.get('os', 'Linux')),
                'type': 'linux',
                'user': user,
                'os_info': os_info
            }
            
            return result
        except:
            return None
