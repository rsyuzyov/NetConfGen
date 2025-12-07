import logging
from pypsexec.client import Client
from smbprotocol.exceptions import SMBAuthenticationError, LogonFailure
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
        
        try:
            logger.debug(f"PsExec: Connecting to {ip} as {user}...")
            
            c = Client(ip, username=user, password=password)
            c.connect()
            
            try:
                # We need to run creation of service to execute commands
                # pypsexec client manages the service creation/deletion automatically 
                # if we use run_executable or wrapper methods.
                # However, for simple commands, creating the service once or letting valid logic handle it is fine.
                c.create_service()
                
                # Get Hostname
                stdout, stderr, rc = c.run_executable("cmd.exe", arguments="/c hostname")
                hostname = stdout.decode('utf-8').strip()
                
                if not hostname:
                    logger.debug(f"PsExec: Empty hostname returned")
                    # If hostname failed, probably something wrong, but we can try to cleanup
                    c.remove_service()
                    c.disconnect()
                    return None

                logger.debug(f"PsExec: Got hostname: {hostname}")

                # Get OS Info
                stdout_os, stderr_os, rc_os = c.run_executable("cmd.exe", arguments="/c wmic os get Caption /value")
                os_output = stdout_os.decode('utf-8').strip()
                
                os_name = "Windows"
                for line in os_output.split('\n'):
                     if 'caption=' in line.lower():
                        os_name = line.split('=', 1)[1].strip()
                        break
                
                # Cleanup service
                c.remove_service()
                c.disconnect()
                
                return {
                    'hostname': hostname,
                    'os': os_name,
                    'type': 'windows',
                    'user': user,
                    'auth_method': 'psexec'
                }
                
            except Exception as e:
                # Always try to cleanup if something inside failed
                try:
                    c.remove_service()
                    c.disconnect()
                except:
                    pass
                raise e

        except (SMBAuthenticationError, LogonFailure):
            logger.debug(f"PsExec: Authentication failed for {user}@{ip}")
            return None
        except Exception as e:
            logger.debug(f"PsExec: Connection failed to {ip}: {e}")
            return None

