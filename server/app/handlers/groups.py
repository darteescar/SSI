import logging
from common.Message import Message

_log = logging.getLogger("group")


class GroupHandlerMixin:
    def _sync_group_contacts(self, group_name: str, new_member: str) -> None:
        """Após new_member entrar no grupo, adiciona-o como contacto mútuo de todos os membros."""
        members = self.user_manager.get_group_members(group_name)
        for member in members:
            if member == new_member:
                continue
            self.user_manager.add_contact(new_member, member)
            self.user_manager.add_contact(member, new_member)

    def handle_GROUP(self, msg: Message) -> None:
        group_name = msg.group_name
        members    = [m.strip() for m in msg.members]
        if not members:
            self._session.send(Message.error("Deves especificar pelo menos um membro para o grupo."))
            return
        if self.user_manager.exists_group(group_name):
            self._session.send(Message.error(f"'{group_name}' já existe."))
            return
        for member in members:
            if not self.user_manager.exists(member):
                self._session.send(Message.error(f"Utilizador '{member}' não encontrado."))
                return
        if not all(m in self.user_manager.get_contacts(self.username) for m in members):
            self._session.send(Message.error(
                "Todos os membros do grupo devem estar nos teus contactos."))
            return
        if not self.user_manager.create_group(group_name, members, self.username):
            self._session.send(Message.error(f"Erro ao criar o grupo '{group_name}'."))
            return
        _log.info(f"grupo '{group_name}' criado com convites para {members} — criador deve gerar a sua sender key e distribui-la via E2E par-a-par")
        self._session.send(Message.resp_create_group(group_name))

    def handle_DELETE_GROUP(self, msg: Message) -> None:
        group_name = msg.group_name
        if not group_name:
            self._session.send(Message.error("Payload inválido para DELETE_GROUP."))
            return
        if not self.user_manager.exists_group(group_name):
            self._session.send(Message.error(f"Grupo '{group_name}' não encontrado."))
            return
        if self.user_manager.get_group_owner(group_name) != self.username:
            self._session.send(Message.error("Só o dono do grupo o pode apagar."))
            return
        if not self.user_manager.delete_group(group_name, self.username):
            self._session.send(Message.error(f"Erro ao apagar o grupo '{group_name}'."))
            return
        self._session.send(Message.resp_delete_group(group_name))

    def handle_LEAVE(self, msg: Message) -> None:
        group_name = msg.group_name
        if not group_name:
            self._session.send(Message.error("Payload inválido para LEAVE."))
            return
        if not self.user_manager.exists_group(group_name):
            self._session.send(Message.error(f"Grupo '{group_name}' não encontrado."))
            return
        if self.username not in self.user_manager.get_group_members(group_name):
            self._session.send(Message.error(f"Não és membro do grupo '{group_name}'."))
            return
        if self.user_manager.get_group_owner(group_name) == self.username:
            self._session.send(Message.error("O dono do grupo não pode sair do grupo."))
            return
        remaining = self.user_manager.get_group_members(group_name)
        remaining = [m for m in remaining if m != self.username]
        self.user_manager.leave_group(group_name, self.username)
        _log.info(f"saída voluntária do grupo '{group_name}' — {len(remaining)} membro(s) remanescente(s) serão instruídos a rodar a sua sender key (forward secrecy face ao ex-membro)")
        self._session.send(Message.resp_leave_group(group_name))
        notify = Message.push_group_member_left(group_name, self.username)
        online_count = 0
        offline_count = 0
        for member in remaining:
            handler = self.user_manager.get_handler(member)
            if handler:
                handler.push_to_client(notify)
                online_count += 1
            else:
                self.user_manager.enqueue_group_notification(
                    member, "GROUP_MEMBER_LEFT", group_name, self.username)
                offline_count += 1
        _log.info(f"notificações GROUP_MEMBER_LEFT do grupo '{group_name}': {online_count} entregue(s) imediatamente, {offline_count} enfileirada(s) para entrega quando o membro reconectar")

    def handle_GROUPS(self) -> None:
        groups = self.user_manager.get_groups(self.username)
        if not groups:
            self._session.send(Message.error("Não és membro de nenhum grupo."))
            return
        self._session.send(Message.resp_groups(groups=groups))

    def handle_ACCEPT(self, msg: Message) -> None:
        group_name = msg.group_name
        if not group_name:
            self._session.send(Message.error("Payload inválido para ACCEPT."))
            return
        if not self.user_manager.exists_group(group_name):
            self._session.send(Message.error(f"Grupo '{group_name}' não encontrado."))
            return
        if self.user_manager.get_group_owner(group_name) == self.username:
            self._session.send(Message.error(
                "O dono do grupo não pode aceitar um convite para o próprio grupo."))
            return
        if not self.user_manager.accept_invite(group_name, self.username):
            self._session.send(Message.error(
                f"Erro ao aceitar o convite para o grupo '{group_name}'."))
            return
        self._sync_group_contacts(group_name, self.username)
        members = self.user_manager.get_group_members(group_name)
        _log.info(f"convite para o grupo '{group_name}' aceite — membros actuais: {members}. Cliente que aceitou deve gerar a sua sender key e distribuí-la aos restantes via E2E par-a-par")
        self._session.send(Message.resp_accept_group(group_name))
        notify = Message.push_group_member_joined(group_name, self.username)
        online_count = 0
        offline_count = 0
        for member in members:
            if member == self.username:
                continue
            handler = self.user_manager.get_handler(member)
            if handler:
                handler.push_to_client(notify)
                online_count += 1
            else:
                self.user_manager.enqueue_group_notification(
                    member, "GROUP_MEMBER_JOINED", group_name, self.username)
                offline_count += 1
        _log.info(f"notificações GROUP_MEMBER_JOINED do grupo '{group_name}': {online_count} entregue(s) imediatamente (irão distribuir SK ao novo membro), {offline_count} enfileirada(s) para entrega quando o membro reconectar")

    def handle_REJECT(self, msg: Message) -> None:
        group_name = msg.group_name
        if not group_name:
            self._session.send(Message.error("Payload inválido para REJECT."))
            return
        if not self.user_manager.exists_group(group_name):
            self._session.send(Message.error(f"Grupo '{group_name}' não encontrado."))
            return
        if self.user_manager.get_group_owner(group_name) == self.username:
            self._session.send(Message.error(
                "O dono do grupo não pode rejeitar um convite para o próprio grupo."))
            return
        if not self.user_manager.reject_invite(group_name, self.username):
            self._session.send(Message.error(
                f"Erro ao rejeitar o convite para o grupo '{group_name}'."))
            return
        self._session.send(Message.resp_reject_group(group_name))

    def handle_INVITES(self) -> None:
        invites = self.user_manager.get_invites(self.username)
        if not invites:
            self._session.send(Message.error("Não tens convites pendentes."))
            return
        self._session.send(Message.resp_group_invites(invites=invites))

    def handle_GROUP_ADD_MEMBER(self, msg: Message) -> None:
        group_name = msg.group_name
        new_member = msg.info
        if not group_name or not new_member:
            self._session.send(Message.error("Payload inválido para GROUP_ADD_MEMBER."))
            return
        if not self.user_manager.exists_group(group_name):
            self._session.send(Message.error(f"Grupo '{group_name}' não encontrado."))
            return
        if new_member not in self.user_manager.get_contacts(self.username):
            self._session.send(Message.error(f"'{new_member}' não está nos teus contactos."))
            return
        ok, reason = self.user_manager.add_group_member(group_name, new_member, self.username)
        if not ok:
            self._session.send(Message.error(reason))
            return
        self._session.send(Message.resp_add_group_member(group_name, new_member))

    def handle_GROUP_KICK_MEMBER(self, msg: Message) -> None:
        group_name = msg.group_name
        member     = msg.info
        if not group_name or not member:
            self._session.send(Message.error("Payload inválido para GROUP_KICK_MEMBER."))
            return
        if not self.user_manager.exists_group(group_name):
            self._session.send(Message.error(f"Grupo '{group_name}' não encontrado."))
            return
        ok, reason = self.user_manager.kick_group_member(group_name, member, self.username)
        if not ok:
            self._session.send(Message.error(reason))
            return
        remaining = self.user_manager.get_group_members(group_name)
        remaining = [m for m in remaining if m != member]
        _log.info(f"expulsão de '{member}' do grupo '{group_name}' — {len(remaining)} membro(s) remanescente(s) serão instruídos a rodar a sua sender key (forward secrecy face ao expulso)")
        self._session.send(Message.resp_kick_group_member(group_name, member))
        notify = Message.push_group_member_left(group_name, member)
        online_count = 0
        offline_count = 0
        for m in remaining:
            handler = self.user_manager.get_handler(m)
            if handler:
                handler.push_to_client(notify)
                online_count += 1
            else:
                self.user_manager.enqueue_group_notification(
                    m, "GROUP_MEMBER_LEFT", group_name, member)
                offline_count += 1
        _log.info(f"notificações GROUP_MEMBER_LEFT (expulsão) do grupo '{group_name}': {online_count} entregue(s) imediatamente, {offline_count} enfileirada(s)")
