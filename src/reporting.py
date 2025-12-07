import csv
import json
import yaml
import os
import logging
from datetime import datetime
import html

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, storage, output_dir='output'):
        self.storage = storage
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def _get_vendor(self, host):
        """Получает вендор из хоста."""
        return host.get('vendor', '')
    
    def _format_ports(self, ports):
        """Форматирует список портов в строку."""
        if not ports:
            return ''
        if isinstance(ports, list):
            return ', '.join(map(str, sorted(ports)))
        return str(ports)

    def _format_services(self, services):
        """Форматирует список сервисов в строку."""
        if not services:
            return ''
        if isinstance(services, list):
            return ', '.join(services)
        return str(services)

    def _ip_to_int(self, ip):
        """Convert IP address to integer for proper sorting."""
        try:
            parts = ip.split('.')
            return int(parts[0]) * 16777216 + int(parts[1]) * 65536 + int(parts[2]) * 256 + int(parts[3])
        except:
            return 0

    def _sort_hosts_by_ip(self, hosts):
        """Sort hosts list by IP address."""
        return sorted(hosts, key=lambda h: self._ip_to_int(h.get('ip', '')))

    def _sort_data_by_ip(self, data):
        """Sort data dictionary by IP address."""
        return dict(sorted(data.items(), key=lambda x: self._ip_to_int(x[0])))

    def generate_all(self):
        data = self.storage.data
        hosts = self._sort_hosts_by_ip(list(data.values()))
        sorted_data = self._sort_data_by_ip(data)
        
        self._generate_hosts_txt(hosts)
        self._generate_csv(hosts)
        self._generate_json(sorted_data)
        self._generate_ansible_inventory(hosts)
        self._generate_ssh_config(hosts)
        self._generate_html(hosts)
        
        logger.info(f"Reports generated in {self.output_dir}")

    def _generate_hosts_txt(self, hosts):
        with open(os.path.join(self.output_dir, 'hosts.txt'), 'w', encoding='utf-8') as f:
            for h in hosts:
                f.write(f"{h['ip']}\n")

    def _generate_csv(self, hosts):
        keys = ['ip', 'mac', 'vendor', 'hostname', 'os', 'type', 'deep_scan_status', 'auth_method', 'open_ports', 'services', 'last_updated']
        with open(os.path.join(self.output_dir, 'scan_report.csv'), 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
            writer.writeheader()
            for host in hosts:
                row = {k: host.get(k, '') for k in keys}
                row['vendor'] = self._get_vendor(host)
                # Форматируем порты как строку
                if 'open_ports' in row and isinstance(row['open_ports'], list):
                    row['open_ports'] = self._format_ports(row['open_ports'])
                # Форматируем сервисы как строку
                if 'services' in row and isinstance(row['services'], list):
                    row['services'] = self._format_services(row['services'])
                writer.writerow(row)

    def _generate_json(self, data):
        with open(os.path.join(self.output_dir, 'scan_report.json'), 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
        with open(os.path.join(self.output_dir, 'scan_report.yaml'), 'w', encoding='utf-8') as f:
            yaml.dump(data, f, allow_unicode=True)

    def _generate_ansible_inventory(self, hosts):
        inventory = {
            'all': {
                'children': {
                    'windows': {'hosts': {}},
                    'linux': {'hosts': {}},
                    'mikrotik': {'hosts': {}},
                    'unknown': {'hosts': {}}
                }
            }
        }
        
        secrets = {}

        for h in hosts:
            ip = h['ip']
            # Use hostname if available, else IP
            name = h.get('hostname') if h.get('hostname') else ip
            
            group = 'unknown'
            if h.get('type') == 'windows':
                group = 'windows'
            elif h.get('type') == 'linux':
                group = 'linux'
            elif h.get('type') == 'mikrotik':
                group = 'mikrotik'
            else:
                # Check if it's MikroTik by vendor (for network, server, or unknown types)
                vendor = h.get('vendor', '').lower()
                if 'mikrotik' in vendor or 'routerboard' in vendor:
                    group = 'mikrotik'
                elif h.get('type') == 'network':
                    group = 'unknown'  # Other network equipment goes to unknown
            
            inventory['all']['children'][group]['hosts'][name] = {'ansible_host': ip}
            
            # Secrets
            if h.get('deep_scan_status') == 'completed' and h.get('user'):
                # We don't have the password here easily unless we store it in storage (unsafe)
                # or match it back from config.
                # For security, let's just add the user.
                # If user wants passwords in inventory, we'd need to change storage logic.
                # Let's assume we just put user.
                secrets[name] = {
                    'ansible_user': h['user']
                }
                if h.get('auth_method') == 'winrm':
                    secrets[name]['ansible_connection'] = 'winrm'
                    secrets[name]['ansible_winrm_server_cert_validation'] = 'ignore'

        with open(os.path.join(self.output_dir, 'inventory.yaml'), 'w', encoding='utf-8') as f:
            yaml.dump(inventory, f, allow_unicode=True)
            
        with open(os.path.join(self.output_dir, 'secrets.yaml'), 'w', encoding='utf-8') as f:
            yaml.dump(secrets, f, allow_unicode=True)

    def _generate_ssh_config(self, hosts):
        config_lines = []
        # Keep track of used host aliases to avoid duplicates
        used_aliases = set()

        for h in hosts:
            if h.get('deep_scan_status') == 'completed' and h.get('auth_method') in ('ssh', 'ssh_key'):
                ip = h['ip']
                hostname = h.get('hostname')
                user = h.get('user')
                key_path = h.get('key_path')

                # Determine Host alias
                # Use hostname if available and not empty, otherwise use IP
                # Clean hostname to be valid for SSH config (basic check)
                if hostname:
                    alias = hostname.split('.')[0] # Use short hostname for convenience
                else:
                    alias = ip
                
                # Ensure unique alias
                base_alias = alias
                counter = 1
                while alias in used_aliases:
                    alias = f"{base_alias}-{counter}"
                    counter += 1
                used_aliases.add(alias)

                config_lines.append(f"Host {alias}")
                config_lines.append(f"    HostName {ip}")
                if user:
                    config_lines.append(f"    User {user}")
                if key_path:
                    config_lines.append(f"    IdentityFile {key_path}")
                
                # Useful defaults for scanning results where keys might change or are unknown
                config_lines.append("    StrictHostKeyChecking no") 
                config_lines.append("    UserKnownHostsFile /dev/null")
                config_lines.append("")
        
        with open(os.path.join(self.output_dir, 'ssh_config'), 'w', encoding='utf-8') as f:
            f.write('\n'.join(config_lines))

    def _generate_html(self, hosts):
        """
        Генерирует HTML-отчет с результатами сканирования.
        
        Args:
            hosts: Список словарей хостов, содержащих данные сканирования
        
        Returns:
            None (записывает файл на диск)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Helper function to escape HTML and handle None values
        def escape_value(value):
            if value is None or value == '':
                return ''
            return html.escape(str(value))
        
        # Helper function to format datetime
        def format_datetime(dt_str):
            if not dt_str:
                return ''
            try:
                dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                return str(dt_str)
        
        # Build table rows
        table_rows = []
        for host in hosts:
            host_type = host.get('type', '')
            deep_scan_status = host.get('deep_scan_status', '')
            
            # Determine CSS class for host type
            type_class = f"host-{host_type}"
            
            # Add deep scan completed class if applicable
            row_class = type_class
            if deep_scan_status == 'completed':
                row_class += " deep-scan-completed"
            
            row = f"""                <tr class="{row_class}">
                    <td>{escape_value(host.get('ip'))}</td>
                    <td>{escape_value(host.get('mac'))}</td>
                    <td>{escape_value(self._get_vendor(host))}</td>
                    <td>{escape_value(host.get('hostname'))}</td>
                    <td>{escape_value(host.get('os'))}</td>
                    <td>{escape_value(host.get('type'))}</td>
                    <td>{escape_value(host.get('deep_scan_status'))}</td>
                    <td>{escape_value(host.get('auth_method'))}</td>
                    <td>{escape_value(self._format_ports(host.get('open_ports')))}</td>
                    <td>{escape_value(self._format_services(host.get('services')))}</td>
                    <td>{escape_value(format_datetime(host.get('last_updated')))}</td>
                </tr>
"""
            table_rows.append(row)
        
        # Load template
        template_path = os.path.join(os.path.dirname(__file__), 'report_template.html')
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
        except Exception as e:
            logger.error(f"Failed to load HTML template: {e}")
            return
        
        # Fill template
        html_content = template.format(
            timestamp=escape_value(timestamp),
            table_rows=''.join(table_rows),
            total_hosts=len(hosts)
        )
        
        # Write to file
        output_path = os.path.join(self.output_dir, 'scan_report.html')
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report generated: {output_path}")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")
