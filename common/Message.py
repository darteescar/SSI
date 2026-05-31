from dataclasses import dataclass
from common.messages.base import BaseMessage
from common.messages.auth import AuthMessageMixin
from common.messages.contacts import ContactsMessageMixin
from common.messages.chat import ChatMessageMixin
from common.messages.groups import GroupMessageMixin

@dataclass
class Message(BaseMessage, AuthMessageMixin, ContactsMessageMixin, ChatMessageMixin, GroupMessageMixin):
    """Classe agregadora que engloba a estrutura e serialização base, mais os métodos de request/response em Mixins."""
    pass
