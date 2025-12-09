import logging
import socket
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

class PortScanner:
    def __init__(self, storage):
        self.storage = storage
    
    def _check_port(self, ip, port, timeout=1):
        """Проверяет, открыт ли TCP порт."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port, result == 0
        except:
            return port, False
    
    def _check_multiple_ports(self, ip, ports, timeout=1, max_workers=50):
        """
        Параллельная проверка нескольких портов.
        
        Args:
            ip: IP адрес хоста
            ports: список портов для проверки
            timeout: таймаут для каждого порта
            max_workers: максимальное количество потоков
            
        Returns:
            dict: {port: True/False}
        """
        results = {}
        with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as executor:
            futures = {executor.submit(self._check_port, ip, port, timeout): port for port in ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                results[port] = is_open
        
        return results
    
    def load_ports_from_file(self, ports_file):
        """
        Загружает порты из JSON файла.
        
        Args:
            ports_file: путь к файлу с портами (например, ports.json)
            
        Returns:
            list: список портов (int)
        """
        try:
            with open(ports_file, 'r', encoding='utf-8') as f:
                ports_dict = json.load(f)
                return [int(port) for port in ports_dict.keys()]
        except Exception as e:
            logger.error(f"Ошибка при загрузке портов из {ports_file}: {e}")
            return []
    
    def parse_ports_string(self, ports_str):
        """
        Парсит строку с портами.
        
        Args:
            ports_str: строка вида "22, 80, 443" или "*"
            
        Returns:
            list: список портов (int) или None для всех портов
        """
        if ports_str == "*":
            return None  # Все порты (1-65535)
        
        ports = []
        for part in ports_str.split(','):
            part = part.strip()
            if part.isdigit():
                ports.append(int(part))
        
        return ports

    def scan_host_ports(self, ip, ports, timeout=1):
        """
        Сканирует порты на одном хосте.
        
        Args:
            ip: IP адрес хоста
            ports: список портов для проверки или None для всех портов
            timeout: таймаут для каждого порта
            
        Returns:
            dict: информация о хосте с открытыми портами
        """
        logger.info(f"Сканирование портов на {ip}...")
        
        # Если ports=None, сканируем все порты (1-65535)
        if ports is None:
            logger.info(f"{ip}: Сканирование всех портов (1-65535)...")
            ports = list(range(1, 65536))
        
        # Проверяем порты
        port_status = self._check_multiple_ports(ip, ports, timeout=timeout)
        open_ports = sorted([port for port, is_open in port_status.items() if is_open])
        
        if open_ports:
            logger.info(f"{ip}: Найдено открытых портов: {len(open_ports)}")
            logger.debug(f"{ip}: Открытые порты: {open_ports}")
        else:
            logger.info(f"{ip}: Открытых портов не найдено")
        
        # Получаем существующую информацию о хосте
        existing_host = self.storage.get_host(ip)
        
        # Обновляем информацию о портах
        result = {
            'ip': ip,
            'open_ports': open_ports,
            'port_scan_completed': True
        }
        
        # Сохраняем в storage
        self.storage.update_host(ip, result)
        
        return result
    
    def scan_all_hosts(self, hosts=None, ports=None, timeout=1, concurrency=10):
        """
        Сканирует порты на всех хостах.
        
        Args:
            hosts: список IP адресов или None для всех хостов из storage
            ports: список портов для проверки или None для всех портов
            timeout: таймаут для каждого порта
            concurrency: количество одновременно сканируемых хостов
            
        Returns:
            list: список результатов сканирования
        """
        # Если hosts не указан, берем все хосты из storage
        if hosts is None:
            hosts = list(self.storage.data.keys())
            logger.info(f"Сканирование всех хостов из storage: {len(hosts)} хостов")
        else:
            logger.info(f"Сканирование указанных хостов: {len(hosts)} хостов")
        
        if not hosts:
            logger.warning("Нет хостов для сканирования")
            return []
        
        results = []
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(self.scan_host_ports, ip, ports, timeout): ip for ip in hosts}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    ip = futures[future]
                    logger.error(f"Ошибка при сканировании {ip}: {e}")
        
        logger.info(f"Сканирование завершено: {len(results)} хостов")
        return results
