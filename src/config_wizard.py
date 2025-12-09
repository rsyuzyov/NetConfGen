import yaml
import os
import sys
import json

def get_input(prompt, default=None):
    """Helper to get user input with a default value."""
    if default:
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default
    else:
        return input(f"{prompt}: ").strip()

def create_config():
    print("=== NetConfGen Configuration Wizard ===")
    print("Config file not found. Let's create one.")

    config = {}

    # 1. Targets
    targets = []
    print("\n--- Targets ---")
    print("Enter subnets to scan (e.g., 192.168.0.0/24). Enter empty line to finish.")
    while True:
        target = input("Subnet: ").strip()
        if not target:
            if not targets:
                print("At least one target is required.")
                continue
            break
        targets.append(target)
    config['targets'] = targets

    # 2. Credentials
    credentials = []
    print("\n--- Credentials ---")
    print("Add credentials for Deep Scan (SSH/WinRM). Enter empty user to finish.")
    while True:
        user = input("Username: ").strip()
        if not user:
            break
        protocol = get_input("Protocol (ssh/winrm)", "ssh").lower()
        auth_method = "password"
        key_path = None
        password = ""

        if protocol == "ssh":
            auth_method = get_input("SSH auth (password/key)", "password").lower()
            if auth_method == "key":
                key_path = get_input("Path to private key")
            else:
                password = get_input("Password")
        else:
            password = get_input("Password")

        account = {"user": user}
        if key_path:
            account["key_path"] = key_path
        if password:
            account["password"] = password

        existing_protocol = next((c for c in credentials if c.get("protocol") == protocol), None)
        if existing_protocol:
            existing_protocol["accounts"].append(account)
        else:
            credentials.append({
                "protocol": protocol,
                "accounts": [account]
            })

    config['credentials'] = credentials

    # 3. Settings
    print("\n--- Settings ---")
    config['concurrency'] = int(get_input("Deep Scan Concurrency (threads)", "10"))
    config['ports_file'] = get_input("Ports file name", "ports.json")

    exclusions_input = get_input("Exclusions (comma-separated IPs)", "")
    config['exclusions'] = [ip.strip() for ip in exclusions_input.split(',')] if exclusions_input else []

    # Save config.yaml
    config_path = 'config.yaml'
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    
    print(f"\nConfiguration saved to {os.path.abspath(config_path)}")
    
    # Create default ports.json if it doesn't exist
    ports_path = 'ports.json'
    if not os.path.exists(ports_path):
        default_ports = {
            "21": "FTP",
            "22": "SSH",
            "23": "Telnet",
            "25": "SMTP",
            "53": "DNS",
            "80": "HTTP",
            "88": "Kerberos",
            "110": "POP3",
            "135": "RPC",
            "143": "IMAP",
            "161": "SNMP",
            "389": "LDAP",
            "443": "HTTPS",
            "445": "SMB",
            "587": "SMTP-Submission",
            "636": "LDAPS",
            "902": "VMware",
            "993": "IMAPS",
            "995": "POP3S",
            "1433": "MSSQL",
            "1521": "Oracle",
            "1540": "1C",
            "1541": "1C",
            "1560": "1C",
            "1561": "1C",
            "2049": "NFS",
            "3000": "Grafana",
            "3306": "MySQL",
            "3389": "RDP",
            "4040": "Kerio",
            "5000": "Synology-QNAP",
            "5432": "PostgreSQL",
            "5601": "Kibana",
            "5900": "VNC",
            "5901": "VNC",
            "5985": "WinRM",
            "8006": "Proxmox",
            "8080": "HTTP-Alt",
            "8200": "vSphere",
            "8291": "MikroTik-Winbox",
            "8443": "HTTPS-Alt",
            "8728": "MikroTik-API",
            "9090": "Prometheus",
            "9100": "Printer",
            "10000": "Webmin",
            "27017": "MongoDB"
        }
        with open(ports_path, 'w', encoding='utf-8') as f:
            json.dump(default_ports, f, indent=2, ensure_ascii=False)
        print(f"Default ports.json created at {os.path.abspath(ports_path)}")
    
    return config

if __name__ == "__main__":
    create_config()
