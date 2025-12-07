import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class Storage:
    def __init__(self, output_dir='output'):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        self.state_file = os.path.join(output_dir, 'scan_state.json')
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
                return {}
        return {}

    def save(self):
        try:
            # Sort IPs in ascending order
            def ip_to_int(ip):
                """Convert IP address to integer for proper sorting."""
                try:
                    parts = ip.split('.')
                    return int(parts[0]) * 16777216 + int(parts[1]) * 65536 + int(parts[2]) * 256 + int(parts[3])
                except:
                    return 0
            
            sorted_data = dict(sorted(self.data.items(), key=lambda x: ip_to_int(x[0])))
            
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(sorted_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def update_host(self, ip, info):
        """
        Updates information for a specific host.
        Does not overwrite existing non-empty values with empty strings for:
        vendor, hostname, os, type
        """
        if ip not in self.data:
            self.data[ip] = {}
        
        # Поля, которые не должны перезаписываться пустыми значениями
        protected_fields = ['vendor', 'hostname', 'os', 'type']
        
        # Фильтруем info: не перезаписываем защищенные поля, если новое значение пустое
        filtered_info = {}
        for key, value in info.items():
            if key in protected_fields:
                # Если поле защищено и новое значение пустое, а в storage уже есть непустое значение
                existing_value = self.data[ip].get(key)
                # Проверяем: новое значение пустое (None, '', или пустая строка после strip)
                # и существующее значение непустое
                new_is_empty = value is None or (isinstance(value, str) and not value.strip())
                existing_is_non_empty = existing_value and (not isinstance(existing_value, str) or existing_value.strip())
                
                if new_is_empty and existing_is_non_empty:
                    # Пропускаем пустое значение, сохраняем существующее
                    continue
            filtered_info[key] = value
        
        self.data[ip].update(filtered_info)
        # Добавляем дату последнего обновления
        self.data[ip]['last_updated'] = datetime.now().isoformat()
        self.save()

    def get_host(self, ip):
        return self.data.get(ip, {})

    def is_scanned(self, ip):
        """Checks if deep scan was successfully completed for this IP."""
        return self.data.get(ip, {}).get('deep_scan_status') == 'completed'
