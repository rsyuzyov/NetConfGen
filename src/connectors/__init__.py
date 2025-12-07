from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)

class BaseConnector(ABC):
    @abstractmethod
    def connect(self, ip, user, password=None, key_path=None):
        """
        Попытка подключения к хосту.
        
        Args:
            ip (str): IP адрес хоста.
            user (str): Имя пользователя.
            password (str, optional): Пароль.
            key_path (str, optional): Путь к файлу ключа (для SSH).
            
        Returns:
            dict | None: Словарь с информацией о хосте при успешном подключении, иначе None.
                         Структура словаря:
                         {
                             'hostname': str,
                             'os': str,
                             'type': str, # 'linux', 'windows' и т.д.
                             'user': str, # Имя пользователя, под которым удалось подключиться
                             'key_path': str # Если использовался ключ
                         }
        """
        pass
