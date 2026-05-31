import os
import sys

_SERVER_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_SERVER_DIR)
sys.path.insert(0, _SERVER_DIR)
sys.path.insert(0, _PROJECT_DIR)

from persistence.managers.base import BaseManager
from persistence.managers.users import UserManagerMixin
from persistence.managers.contacts import ContactsManagerMixin
from persistence.managers.groups import GroupManagerMixin
from persistence.managers.chats import ChatManagerMixin
from persistence.managers.prekeys import PrekeysManagerMixin


class ServerManager(BaseManager, UserManagerMixin, ContactsManagerMixin,
                    GroupManagerMixin, ChatManagerMixin, PrekeysManagerMixin):
    """Fachada de persistência — agrega todos os managers por domínio."""
    pass
