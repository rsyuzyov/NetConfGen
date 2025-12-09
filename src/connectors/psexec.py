import logging
from pypsexec.client import Client
from smbprotocol.exceptions import SMBAuthenticationError, LogonFailure, SMBConnectionClosed
from . import BaseConnector

logger = logging.getLogger(__name__)

class PsExecConnector(BaseConnector):
    def connect(self, ip, user, password=None, key_path=None):
        """Try connecting via PsExec (pypsexec) with credentials.
        
        Returns:
            dict | None: Result dict on success, None on failure.
        """
        if not user or not password:
            logger.debug(f"PsExec: User and password are required")
            return None

        # pypsexec works on Linux/Windows/Mac via Python
        # Logic: 
        # 1. Connect
        # 2. Authenticate
        # 3. Run command (hostname, os_info)
        
        service_created = False
        try:
            logger.debug(f"PsExec: Connecting to {ip} as {user}...")
            with Client(ip, username=user, password=password) as c:
                c.connect()

                try:
                    # Создаем сервис один раз; удаляем в finally ниже
                    c.create_service()
                    service_created = True

                    # Get Hostname
                    stdout, stderr, rc = c.run_executable("cmd.exe", arguments="/c hostname")
                    hostname = stdout.decode('utf-8').strip()

                    if not hostname:
                        logger.debug("PsExec: Empty hostname returned")
                        return None

                    logger.debug(f"PsExec: Got hostname: {hostname}")

                    # Get OS Info
                    stdout_os, stderr_os, rc_os = c.run_executable(
                        "cmd.exe",
                        arguments="/c wmic os get Caption /value",
                    )
                    os_output = stdout_os.decode('utf-8').strip()

                    os_name = "Windows"
                    for line in os_output.split('\n'):
                        if 'caption=' in line.lower():
                            os_name = line.split('=', 1)[1].strip()
                            break

                    return {
                        'hostname': hostname,
                        'os': os_name,
                        'type': 'windows',
                        'user': user,
                        'auth_method': 'psexec'
                    }
                finally:
                    if service_created:
                        try:
                            c.remove_service()
                        except Exception as cleanup_err:
                            logger.debug(f"PsExec: remove_service cleanup error for {ip}: {cleanup_err}")
        except (SMBAuthenticationError, LogonFailure):
            logger.debug(f"PsExec: Authentication failed for {user}@{ip}")
            return None
        except SMBConnectionClosed as e:
            logger.debug(f"PsExec: SMB connection closed for {ip}: {e}")
            return None
        except Exception as e:
            logger.debug(f"PsExec: Connection failed to {ip}: {e}")
            return None

