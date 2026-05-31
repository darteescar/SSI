from common.MsgType import MsgType

class ChatMessageMixin:
    # ── Mensagens ─────────────────────────────────────────────────────────────

    @classmethod
    def req_chat(cls, recipient: str):
        return cls(MsgType.CHAT, {"to": recipient}, recipient=recipient)

    @classmethod
    def req_chat_leave(cls, recipient: str):
        return cls(MsgType.CHAT_LEAVE, {"to": recipient}, recipient=recipient)

    @classmethod
    def resp_chat(cls, chat: list[dict], is_group: bool = False):
        return cls(MsgType.OK, {
            "chat":     chat,
            "is_group": is_group,
        }, recipient="")

    @classmethod
    def req_send(cls, sender: str, recipient: str, text: str, timestamp: str):
        return cls(MsgType.SEND, {
            "to": recipient,
            "from_": sender,
            "text": text,
            "timestamp": timestamp
        }, 
        recipient=recipient)
    
    @classmethod
    def resp_send(cls, sender: str, recipient: str, text: str, timestamp: str):
        return cls(MsgType.OK, {
            "to": recipient,
            "from_": sender,
            "text": text,
            "timestamp": timestamp
        },)

    @classmethod
    def send_msg(cls, sender: str, recipient: str, text: str, timestamp: str):
        return cls(MsgType.RECEIVE, {
            "to": recipient,
            "from_": sender,
            "text": text,
            "timestamp": timestamp
        }, recipient=recipient)

    # ── Mensagens de grupo ────────────────────────────────────────────────────

    @classmethod
    def req_group_send(cls, group_name: str, payload: str, timestamp: str):
        """payload = base64 do blob cifrado com sender key."""
        return cls(MsgType.GROUP_SEND, {
            "group_name": group_name,
            "payload":    payload,
            "timestamp":  timestamp,
        })

    @classmethod
    def resp_group_send(cls, group_name: str, msg_id: int, sender: str, timestamp: str):
        return cls(MsgType.OK, {
            "group_name": group_name,
            "msg_id":     msg_id,
            "from_":      sender,
            "to":         group_name,
            "timestamp":  timestamp,
        })

    @classmethod
    def group_receive(cls, group_name: str, msg_id: int, sender: str, payload: str, timestamp: str):
        """payload = blob cifrado opaco para relay."""
        return cls(MsgType.GROUP_RECEIVE, {
            "group_name": group_name,
            "msg_id":     msg_id,
            "from_":      sender,
            "payload":    payload,
            "timestamp":  timestamp,
        })

    @classmethod
    def req_group_ack(cls, group_name: str, msg_id: int):
        return cls(MsgType.GROUP_ACK, {
            "group_name": group_name,
            "msg_id":     msg_id,
        })

    @classmethod
    def req_group_sk_dist(cls, group_name: str, to: str, msg_id: str, payload_b64: str):
        """Distribui a nossa sender key a um membro via canal E2E par-a-par.
        Enviado como E2E_MSG opaco com type='sk_dist' dentro do payload."""
        return cls(MsgType.E2E_MSG, {
            "to":      to,
            "msg_id":  msg_id,
            "payload": payload_b64,
        })
