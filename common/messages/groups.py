from common.MsgType import MsgType

class GroupMessageMixin:
    # ── Grupos ────────────────────────────────────────────────────────────────

    @classmethod
    def req_create_group(cls, group_name: str, members: list[str]):
        return cls(MsgType.GROUP, {"group_name": group_name, "members": members})
    
    @classmethod
    def resp_create_group(cls, group_name: str):
        return cls(MsgType.OK, {"info": f"Grupo '{group_name}' criado com sucesso."})

    @classmethod
    def req_leave_group(cls, group_name: str):
        return cls(MsgType.LEAVE, {"group_name": group_name})
    
    @classmethod
    def resp_leave_group(cls, group_name: str):
        return cls(MsgType.OK, {"info": f"Saída do grupo '{group_name}' efetuada com sucesso."})

    @classmethod
    def req_groups(cls):
        return cls(MsgType.GROUPS)

    @classmethod
    def resp_groups(cls, groups: dict[str, list[str]]):
        return cls(MsgType.OK, {"groups": groups})

    @classmethod
    def req_delete_group(cls, group_name: str):
        return cls(MsgType.DELETE_GROUP, {"group_name": group_name})

    @classmethod
    def resp_delete_group(cls, group_name: str):
        return cls(MsgType.OK, {"info": f"Grupo '{group_name}' apagado com sucesso."})

    @classmethod
    def req_accept_group(cls, group_name: str):
        return cls(MsgType.ACCEPT_GROUP, {"group_name": group_name})

    @classmethod
    def resp_accept_group(cls, group_name: str):
        return cls(MsgType.OK, {"info": f"Convite para o grupo '{group_name}' aceite com sucesso."})

    @classmethod
    def req_reject_group(cls, group_name: str):
        return cls(MsgType.REJECT_GROUP, {"group_name": group_name})

    @classmethod
    def resp_reject_group(cls, group_name: str):
        return cls(MsgType.OK, {"info": f"Convite para o grupo '{group_name}' rejeitado com sucesso."})

    @classmethod
    def req_group_invites(cls):
        return cls(MsgType.GROUP_INVITES)

    @classmethod
    def resp_group_invites(cls, invites: list[dict]):
        return cls(MsgType.OK, {"invites": invites})

    @classmethod
    def req_add_group_member(cls, group_name: str, username: str):
        return cls(MsgType.GROUP_ADD_MEMBER, {"group_name": group_name, "info": username})

    @classmethod
    def resp_add_group_member(cls, group_name: str, username: str):
        return cls(MsgType.OK, {"info": f"Convite enviado a '{username}' para o grupo '{group_name}'."})

    @classmethod
    def req_kick_group_member(cls, group_name: str, username: str):
        return cls(MsgType.GROUP_KICK_MEMBER, {"group_name": group_name, "info": username})

    @classmethod
    def resp_kick_group_member(cls, group_name: str, username: str):
        return cls(MsgType.OK, {"info": f"'{username}' foi removido do grupo '{group_name}'."})

    @classmethod
    def push_group_member_left(cls, group_name: str, username: str):
        """Servidor → membros remanescentes: um membro saiu/foi expulso — devem rodar as suas sender keys."""
        return cls(MsgType.GROUP_MEMBER_LEFT, {"group_name": group_name, "info": username})

    @classmethod
    def push_group_member_joined(cls, group_name: str, username: str):
        """Servidor → membros existentes: um novo membro entrou — devem distribuir as suas sender keys ao novo membro."""
        return cls(MsgType.GROUP_MEMBER_JOINED, {"group_name": group_name, "info": username})
