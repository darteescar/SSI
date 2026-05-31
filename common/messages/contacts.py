from common.MsgType import MsgType

class ContactsMessageMixin:
    # ── Utilizadores ─────────────────────────────────────────────────────────

    @classmethod
    def req_add(cls, username: str):
        return cls(MsgType.ADD, {"info": username})
    
    @classmethod
    def resp_add(cls, username: str, cert_pem: str = ""):
        """cert_pem: certificado PEM do utilizador adicionado (emitido pela CA do servidor)."""
        return cls(MsgType.OK, {"info": f"'{username}' adicionado aos contactos.", "cert_pem": cert_pem})
    
    @classmethod
    def req_remove(cls, username: str):
        return cls(MsgType.REMOVE, {"info": username})

    @classmethod
    def resp_remove(cls, username: str):
        return cls(MsgType.OK, {"info": f"'{username}' removido dos contactos."})

    @classmethod
    def req_list_online(cls):
        return cls(MsgType.LIST)

    @classmethod
    def resp_list_online(cls, users: list[str]):
        return cls(MsgType.OK, {"users": users})

    @classmethod
    def req_contacts(cls):
        return cls(MsgType.CONTACTS)

    @classmethod
    def resp_contacts(cls, users: list[str]):
        return cls(MsgType.OK, {"users": users})
