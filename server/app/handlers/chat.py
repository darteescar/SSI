from common.Message import Message


class ChatHandlerMixin:
    def handle_SEND(self, msg: Message) -> None:
        if not msg.to or not msg.text or not msg.timestamp or not msg.from_:
            self._session.send(Message.error("Payload inválido para SEND."))
            return
        if not self.user_manager.exists(msg.to):
            self._session.send(Message.error(f"Utilizador '{msg.to}' não encontrado."))
            return
        if msg.to not in self.user_manager.get_contacts(self.username):
            self._session.send(Message.error(f"'{msg.to}' não está nos teus contactos."))
            return
        if self.user_manager.is_the_other_online_in_chat(self.username, msg.to):
            recipient = self.user_manager.get_handler(msg.to)
            if recipient:
                recipient.push_to_client(
                    Message.send_msg(sender=self.username, recipient=msg.to,
                                     text=msg.text, timestamp=msg.timestamp))
        self.user_manager.save_chat_message(msg)
        self._session.send(Message.resp_send(
            sender=self.username, recipient=msg.to,
            text=msg.text, timestamp=msg.timestamp))

    def handle_CHAT(self, msg: Message) -> None:
        target = msg.to or msg.recipient
        if not target:
            self._session.send(Message.error("Payload inválido para CHAT."))
            return
        if self.user_manager.exists_group(target):
            if not self.user_manager.is_group_member(target, self.username):
                self._session.send(Message.error(f"Não és membro do grupo '{target}'."))
                return
            pending = self.user_manager.open_group_chat(self.username, target)
            for m in pending:
                self._session.send(
                    Message.group_receive(
                        group_name=target,
                        msg_id=m["msg_id"],
                        sender=m["from_"],
                        payload=m["payload"],
                        timestamp=m["timestamp"],
                    )
                )
            self._session.send(Message.resp_chat(chat=[], is_group=True))
        else:
            if not self.user_manager.exists(target):
                self._session.send(Message.error(f"Utilizador '{target}' não encontrado."))
                return
            if target not in self.user_manager.get_contacts(self.username):
                self._session.send(Message.error(f"'{target}' não está nos teus contactos."))
                return
            chat_history = self.user_manager.get_chat_history(self.username, target)
            self.user_manager.set_online_chat(self.username, target, is_online=True)
            self._session.send(Message.resp_chat(chat=chat_history))

    def handle_CHAT_LEAVE(self, msg: Message) -> None:
        target = msg.to
        if not target:
            return
        if self.user_manager.exists_group(target):
            self.user_manager.leave_group_chat(self.username, target)
        else:
            self.user_manager.set_online_chat(self.username, target, is_online=False)

    def handle_GROUP_SEND(self, msg: Message) -> None:
        group_name = msg.group_name
        payload    = msg.payload_b64
        timestamp  = msg.timestamp
        if not group_name or not payload:
            self._session.send(Message.error("Payload inválido para GROUP_SEND."))
            return
        if not self.user_manager.exists_group(group_name):
            self._session.send(Message.error(f"Grupo '{group_name}' não encontrado."))
            return
        if not self.user_manager.is_group_member(group_name, self.username):
            self._session.send(Message.error(f"Não és membro do grupo '{group_name}'."))
            return
        msg_id = self.user_manager.save_group_message(group_name, self.username, payload, timestamp)
        if msg_id is None:
            self._session.send(Message.error("Erro ao guardar mensagem de grupo."))
            return
        for handler in self.user_manager.get_group_online_handlers(group_name, self.username):
            handler.push_to_client(
                Message.group_receive(group_name=group_name, msg_id=msg_id,
                                      sender=self.username, payload=payload, timestamp=timestamp))
        self._session.send(Message.resp_group_send(group_name, msg_id, self.username, timestamp))

    def handle_GROUP_ACK(self, msg: Message) -> None:
        group_name = msg.group_name
        msg_id     = msg.msg_id
        if group_name and msg_id:
            self.user_manager.ack_group_message(group_name, msg_id, self.username)
