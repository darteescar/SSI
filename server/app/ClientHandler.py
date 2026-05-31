import os
import sys

_SERVER_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_SERVER_DIR)
sys.path.insert(0, _SERVER_DIR)
sys.path.insert(0, _PROJECT_DIR)

from app.ServerManager import ServerManager
from common.Message import Message
from common.MsgType import MsgType

from app.handlers.users   import UserHandlerMixin
from app.handlers.groups  import GroupHandlerMixin
from app.handlers.chat    import ChatHandlerMixin
from app.handlers.e2e     import PrekeysHandlerMixin


class ClientHandler(UserHandlerMixin, GroupHandlerMixin, ChatHandlerMixin, PrekeysHandlerMixin):
    def __init__(self, session, username: str, user_manager: ServerManager):
        self._session     = session
        self.username     = username
        self.user_manager = user_manager

    def push_to_client(self, msg: Message) -> None:
        self._session.push_to_client(msg)

    def handle_message(self, msg: Message) -> None:
        match msg.type:
            case MsgType.LOGIN | MsgType.REGISTO:
                self._session.send(Message.error("Já estás autenticado."))
            case MsgType.LOGOUT:
                self.handle_LOGOUT()
            case MsgType.ADD:
                self.handle_ADD(msg)
            case MsgType.REMOVE:
                self.handle_REMOVE(msg)
            case MsgType.LIST:
                self.handle_LIST()
            case MsgType.CONTACTS:
                self.handle_CONTACTS()
            case MsgType.SEND:
                self.handle_SEND(msg)
            case MsgType.GROUP:
                self.handle_GROUP(msg)
            case MsgType.DELETE_GROUP:
                self.handle_DELETE_GROUP(msg)
            case MsgType.LEAVE:
                self.handle_LEAVE(msg)
            case MsgType.GROUPS:
                self.handle_GROUPS()
            case MsgType.ACCEPT_GROUP:
                self.handle_ACCEPT(msg)
            case MsgType.REJECT_GROUP:
                self.handle_REJECT(msg)
            case MsgType.GROUP_INVITES:
                self.handle_INVITES()
            case MsgType.GROUP_ADD_MEMBER:
                self.handle_GROUP_ADD_MEMBER(msg)
            case MsgType.GROUP_KICK_MEMBER:
                self.handle_GROUP_KICK_MEMBER(msg)
            case MsgType.CHAT:
                self.handle_CHAT(msg)
            case MsgType.CHAT_LEAVE:
                self.handle_CHAT_LEAVE(msg)
            case MsgType.GROUP_SEND:
                self.handle_GROUP_SEND(msg)
            case MsgType.GROUP_ACK:
                self.handle_GROUP_ACK(msg)
            case MsgType.PREKEY_UPLOAD:
                self.handle_PREKEY_UPLOAD(msg)
            case MsgType.PREKEY_REQUEST:
                self.handle_PREKEY_REQUEST(msg)
            case MsgType.CERT_REQUEST:
                self.handle_CERT_REQUEST(msg)
            case MsgType.E2E_MSG:
                self.handle_E2E_MSG(msg)
            case MsgType.E2E_ACK:
                self.handle_E2E_ACK(msg)
            case _:
                self._session.send(Message.error(f"Comando desconhecido: {msg.type}"))
