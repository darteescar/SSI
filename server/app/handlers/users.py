from common.Message import Message
from common.MsgType import MsgType


class UserHandlerMixin:
    def handle_LOGOUT(self) -> None:
        self._session.send(Message.resp_logout())
        self.user_manager.desautenticar(self.username)
        print(f"[-] '{self.username}' logged out ({self._session.addr})")
        raise ConnectionResetError("Logout")

    def handle_ADD(self, msg: Message) -> None:
        username_to_add = msg.info
        if not username_to_add:
            self._session.send(Message.error("Payload inválido para ADD."))
            return
        if not self.user_manager.exists(username_to_add):
            self._session.send(Message.error(f"Utilizador '{username_to_add}' não encontrado."))
            return
        if username_to_add == self.username:
            self._session.send(Message.error("Não podes adicionar-te a ti próprio."))
            return
        if not self.user_manager.add_contact(self.username, username_to_add):
            self._session.send(Message.error(f"'{username_to_add}' já está nos teus contactos."))
            return
        cert_pem = self.user_manager.get_user_cert(username_to_add) or ""
        self._session.send(Message.resp_add(username_to_add, cert_pem=cert_pem))

    def handle_REMOVE(self, msg: Message) -> None:
        username_to_remove = msg.info
        if not username_to_remove:
            self._session.send(Message.error("Payload inválido para REMOVE."))
            return
        if username_to_remove == self.username:
            self._session.send(Message.error("Não podes remover-te a ti próprio."))
            return
        if not self.user_manager.remove_contact(self.username, username_to_remove):
            self._session.send(Message.error(
                f"'{username_to_remove}' não está nos teus contactos ou não existe."))
            return
        self._session.send(Message.resp_remove(username_to_remove))

    def handle_LIST(self) -> None:
        online_users = self.user_manager.list_online()
        if not online_users:
            self._session.send(Message.error("Nenhum utilizador online."))
            return
        self._session.send(Message.resp_list_online(users=online_users))

    def handle_CONTACTS(self) -> None:
        contactos = self.user_manager.get_contacts(self.username)
        if not contactos:
            self._session.send(Message.error("Lista de contactos vazia."))
            return
        self._session.send(Message.resp_contacts(users=contactos))
