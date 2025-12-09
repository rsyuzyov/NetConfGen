import socket
import logging
import subprocess
import platform
import re

logger = logging.getLogger(__name__)

# Попытка импорта mac-vendor-lookup
try:
    from mac_vendor_lookup import MacLookup
    HAS_MAC_LOOKUP = True
except ImportError:
    HAS_MAC_LOOKUP = False
    logger.debug("mac-vendor-lookup not installed. Vendor detection will be limited.")

class Fingerprint:
    """
    Класс для fingerprinting хостов.
    Определяет ОС и тип устройства через TTL, баннеры и MAC-адрес.
    Может работать как отдельный шаг для обработки хостов из storage.
    """
    
    def __init__(self, storage=None):
        """
        Args:
            storage: Storage объект (опционально, для работы в режиме шага)
        """
        self.storage = storage
        
        # Инициализация MAC lookup
        if HAS_MAC_LOOKUP:
            try:
                self.mac_lookup = MacLookup()
                # Обновить базу при первом запуске (требует интернет)
                try:
                    self.mac_lookup.update_vendors()
                except Exception:
                    pass  # Если нет интернета, используем существующую базу
            except Exception as e:
                logger.debug(f"Failed to initialize MAC lookup: {e}")
                self.mac_lookup = None
        else:
            self.mac_lookup = None

    # ===== Vendor Detection =====
    def get_vendor_from_mac(self, mac):
        """Получить производителя по MAC адресу."""
        if not mac or not self.mac_lookup:
            return ''

        try:
            vendor = self.mac_lookup.lookup(mac)
            return vendor
        except Exception as e:
            logger.debug(f"MAC lookup failed for {mac}: {e}")
            return ''

    def _detect_device_type_by_vendor(self, vendor):
        """Определение типа устройства по производителю."""
        if not vendor:
            return None

        vendor_lower = vendor.lower()

        # MikroTik devices (check first for specific type)
        mikrotik_vendors = ['mikrotik', 'routerboard']

        # Android devices
        android_vendors = [
            'xiaomi', 'samsung', 'huawei', 'oppo', 'vivo', 'oneplus',
            'realme', 'zte', 'lenovo', 'asus', 'lg electronics',
            'motorola mobility', 'google', 'htc', 'sony mobile',
            'meizu', 'tcl', 'honor', 'nothing technology'
        ]

        # iOS devices
        ios_vendors = ['apple']

        # IoT/Smart home
        iot_vendors = [
            'espressif', 'tuya', 'shelly', 'sonoff', 'tp-link',
            'yeelight', 'philips lighting', 'lifx', 'xiaomi communications'
        ]

        # Network equipment (generic)
        network_vendors = [
            'cisco', 'ubiquiti', 'huawei device',
            'd-link', 'netgear', 'juniper', 'aruba', 'hp'
        ]

        # Printers
        printer_vendors = [
            'hewlett packard', 'canon', 'epson', 'brother', 'xerox', 'ricoh'
        ]

        # Check MikroTik first (before generic network)
        for v in mikrotik_vendors:
            if v in vendor_lower:
                return 'mikrotik'

        for v in android_vendors:
            if v in vendor_lower:
                return 'mobile'

        for v in ios_vendors:
            if v in vendor_lower:
                return 'mobile'

        for v in iot_vendors:
            if v in vendor_lower:
                return 'iot'

        for v in network_vendors:
            if v in vendor_lower:
                return 'network'

        for v in printer_vendors:
            if v in vendor_lower:
                return 'printer'

        return None

    # ===== TTL Analysis =====
    def _ping_ttl(self, ip, timeout=2):
        """Получить TTL через ping."""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            result = subprocess.run(
                ['ping', param, '1', ip],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            output = result.stdout

            # Парсинг TTL
            ttl_match = re.search(r'TTL[=:]?\s*(\d+)', output, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                return ttl
        except Exception as e:
            logger.debug(f"Ping failed for {ip}: {e}")

        return None

    def _analyze_ttl(self, ttl):
        """Определение ОС по TTL значению."""
        if not ttl:
            return {}

        # Windows: 128
        if 110 <= ttl <= 128:
            return {'os': 'Windows', 'type': 'workstation'}
        # Linux/Unix: 64
        elif 50 <= ttl <= 64:
            return {'os': 'Linux/Unix', 'type': 'server'}
        # Network device: 255
        elif ttl > 200:
            return {'os': 'Network Device', 'type': 'network'}

        return {}

    # ===== Banner Grabbing =====
    def _grab_banner(self, ip, port, timeout=1):
        """Получить баннер сервиса."""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)

                # Для HTTP отправляем запрос
                if port in [80, 8080, 8000]:
                    sock.send(b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                # HTTPS (443) пропускаем - требует SSL handshake
                elif port == 443:
                    return None

                # Читаем ответ
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner
        except Exception as e:
            logger.debug(f"Banner grab failed {ip}:{port} - {e}")
            return None

    def _analyze_banners(self, ip):
        """Анализ баннеров с нескольких портов."""
        banners = {}
        result = {}

        # Порты для banner grabbing
        BANNER_PORTS = [22, 80, 8080, 21, 25]

        for port in BANNER_PORTS:
            banner = self._grab_banner(ip, port, timeout=1)
            if banner:
                banners[port] = banner
                logger.debug(f"Banner {ip}:{port} - {banner[:50]}")

        # Анализ SSH (22)
        if 22 in banners:
            ssh_banner = banners[22]
            if 'OpenSSH' in ssh_banner:
                result['os'] = 'Linux/Unix (OpenSSH)'
                result['type'] = 'server'
                return result
            elif 'dropbear' in ssh_banner.lower():
                result['os'] = 'Embedded Linux (Dropbear)'
                result['type'] = 'iot'
                return result

        # Анализ HTTP (80, 8080)
        for port in [80, 8080]:
            if port in banners:
                http_banner = banners[port]
                
                # Ищем Server header
                server_match = re.search(r'Server:\s*([^\r\n]+)', http_banner, re.IGNORECASE)
                if server_match:
                    server = server_match.group(1)
                    server_lower = server.lower()

                    if 'nginx' in server_lower or 'apache' in server_lower:
                        result['os'] = f'Linux ({server})'
                        result['type'] = 'server'
                        return result
                    elif 'iis' in server_lower or 'microsoft' in server_lower:
                        result['os'] = f'Windows ({server})'
                        result['type'] = 'server'
                        return result
                    elif 'printer' in server_lower or 'cups' in server_lower:
                        result['os'] = 'Printer'
                        result['type'] = 'printer'
                        return result

        # Анализ FTP (21)
        if 21 in banners:
            ftp_banner = banners[21]
            if 'Microsoft FTP' in ftp_banner or 'Windows' in ftp_banner:
                result['os'] = 'Windows (FTP)'
                result['type'] = 'server'
                return result
            elif 'vsFTPd' in ftp_banner or 'ProFTPD' in ftp_banner:
                result['os'] = 'Linux (FTP)'
                result['type'] = 'server'
                return result

        return result

    # ===== Main Fingerprinting Method =====
    def lightweight_fingerprint(self, ip, vendor=None, mac=None):
        """
        Легковесный fingerprinting без nmap.

        Args:
            ip: IP адрес
            vendor: MAC vendor (опционально, для fallback)
            mac: MAC адрес (для lookup vendor если не передан)

        Returns:
            dict: {
                'os': str,
                'kernel_version': str,
                'type': str,
                'confidence': str (high/medium/low),
                'method': str (ttl/banner/vendor/none),
                'details': dict
            }
        """
        result = {
            'os': 'Unknown',
            'kernel_version': '',
            'type': 'unknown',
            'hostname': '',
            'confidence': 'low',
            'method': 'none',
            'details': {}
        }

        # 0. Обновить vendor через MAC lookup если нужно
        if not vendor and mac:
            vendor = self.get_vendor_from_mac(mac)
        
        if vendor:
            result['vendor'] = vendor

        # 1. TTL Analysis (быстрый, надежный)
        ttl = self._ping_ttl(ip, timeout=2)
        if ttl:
            result['details']['ttl'] = ttl
            ttl_info = self._analyze_ttl(ttl)
            
            if ttl_info.get('type'):
                result['os'] = ttl_info['os']
                result['type'] = ttl_info['type']
                result['confidence'] = 'medium'
                result['method'] = 'ttl'
                logger.debug(f"Fingerprint {ip} via TTL: {ttl_info}")
                return result

        # 2. Banner Grabbing (более точный)
        banner_info = self._analyze_banners(ip)
        if banner_info.get('type'):
            result['os'] = banner_info['os']
            result['type'] = banner_info['type']
            result['confidence'] = 'high'
            result['method'] = 'banner' if not ttl else 'ttl+banner'
            logger.info(f"Fingerprint {ip} via banner: {banner_info}")
            return result

        # 3. Vendor-based Detection (fallback)
        if vendor:
            device_type = self._detect_device_type_by_vendor(vendor)
            if device_type:
                result['type'] = device_type
                result['os'] = {
                    'mobile': 'Android/iOS',
                    'iot': 'IoT Device',
                    'network': 'Network Equipment',
                    'printer': 'Printer',
                    'mikrotik': 'MikroTik RouterOS'
                }.get(device_type, 'Unknown')
                result['confidence'] = 'low'
                result['method'] = 'vendor'
                logger.info(f"Fingerprint {ip} via vendor: {vendor} -> {device_type}")
                return result

        # Если ничего не сработало
        logger.debug(f"Fingerprint {ip} failed - no methods succeeded")
        return result

    # ===== Backward Compatibility =====
    def fingerprint(self, ip, vendor=None):
        """
        Обратная совместимость со старым API.
        
        Старый формат:
            {'os': str, 'hostname': str, 'type': str}
        """
        # Вызываем новый метод
        fp_result = self.lightweight_fingerprint(ip, vendor=vendor, mac=None)
        
        # Возвращаем в старом формате
        return {
            'os': fp_result['os'],
            'hostname': fp_result.get('hostname', ''),
            'type': fp_result['type']
        }

    # ===== Step Mode Methods =====
    def run(self, host_ip=None, force=False):
        """
        Запускает fingerprinting для хостов из storage.
        
        Args:
            host_ip: IP конкретного хоста (опционально)
            force: Принудительно запустить для всех хостов
        """
        if not self.storage:
            raise ValueError("Storage не инициализирован. Создайте объект с storage для использования run()")
        
        if host_ip:
            # Fingerprint для конкретного хоста
            self._fingerprint_host(host_ip, force)
        else:
            # Fingerprint для всех подходящих хостов
            self._fingerprint_all_hosts(force)
    
    def _fingerprint_host(self, ip, force=False):
        """Fingerprint для одного хоста."""
        host_info = self.storage.get_host(ip)
        
        if not host_info:
            logger.error(f"Хост {ip} не найден в storage")
            return
        
        # Проверяем, нужно ли делать fingerprint
        deep_scan_status = host_info.get('deep_scan_status', '')
        
        if not force and deep_scan_status == 'completed':
            logger.info(f"Хост {ip} уже имеет deep_scan_status=completed, пропускаем")
            return
        
        logger.info(f"Fingerprinting хоста: {ip}")
        
        # Выполняем fingerprinting
        fp_result = self.lightweight_fingerprint(
            ip,
            vendor=host_info.get('vendor'),
            mac=host_info.get('mac')
        )
        
        # Обновляем информацию в storage
        update_data = {
            'os': fp_result.get('os', 'Unknown'),
            'type': fp_result.get('type', 'unknown'),
            'hostname': fp_result.get('hostname', ''),
            'fingerprint_method': fp_result.get('method', 'none'),
            'fingerprint_confidence': fp_result.get('confidence', 'low')
        }
        
        # Добавляем vendor если был определен
        if 'vendor' in fp_result:
            update_data['vendor'] = fp_result['vendor']
        
        self.storage.update_host(ip, update_data)
        
        logger.info(f"  OS: {fp_result.get('os')}, Type: {fp_result.get('type')}, "
                   f"Method: {fp_result.get('method')}, Confidence: {fp_result.get('confidence')}")
    
    def _fingerprint_all_hosts(self, force=False):
        """Fingerprint для всех хостов с deep_scan_status != 'completed'."""
        if not self.storage.data:
            logger.warning("Нет хостов в storage")
            return
        
        # Фильтруем хосты
        hosts_to_scan = []
        for ip, host_info in self.storage.data.items():
            deep_scan_status = host_info.get('deep_scan_status', '')
            
            if force or deep_scan_status != 'completed':
                hosts_to_scan.append(ip)
        
        if not hosts_to_scan:
            logger.info("Нет хостов для fingerprinting (все имеют deep_scan_status=completed)")
            return
        
        logger.info(f"Найдено хостов для fingerprinting: {len(hosts_to_scan)}")
        
        # Выполняем fingerprinting для каждого хоста
        for ip in hosts_to_scan:
            self._fingerprint_host(ip, force=True)  # force=True т.к. уже отфильтровали
        
        logger.info(f"Fingerprinting завершен для {len(hosts_to_scan)} хостов")
