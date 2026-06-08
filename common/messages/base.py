import json
from dataclasses import dataclass, field
from common.MsgType import MsgType

@dataclass
class BaseMessage:
    type: MsgType
    payload: dict = field(default_factory=dict)
    recipient: str = ""

    # ── Serialização ─────────────────────────────────────

    def serialize(self) -> str:
        return json.dumps({
            "type": self.type,
            "payload": self.payload,
            "recipient": self.recipient
        })

    @classmethod
    def deserialize(cls, raw: str) -> "BaseMessage":
        try:
            data = json.loads(raw)
            return cls(
                type=MsgType(data["type"]),
                payload=data.get("payload", {}),
                recipient=data.get("recipient", "")
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError(f"Mensagem inválida: '{raw}' → {e}")

    # ── Acesso ao payload ────────────────────────────

    def get(self, key: str, default=None):
        return self.payload.get(key, default)

    def set(self, key: str, value) -> None:
        self.payload[key] = value

    @property
    def username(self) -> str:   return self.get("username", "")
    @property
    def password(self) -> str:   return self.get("password", "")
    @property
    def info(self) -> str:       return self.get("info", "")
    @property
    def reason(self) -> str:     return self.get("info", "")
    @property
    def users(self) -> list:     return self.get("users", [])
    @property
    def to(self) -> str:         return self.get("to", "")
    @property
    def from_(self) -> str:      return self.get("from_", "") 
    @property
    def text(self) -> str:       return self.get("text", "")
    @property
    def timestamp(self) -> str:  return self.get("timestamp", "")
    @property
    def inbox(self) -> list:     return self.get("inbox", [])
    @property
    def group_name(self) -> str: return self.get("group_name", "")
    @property
    def members(self) -> list:   return self.get("members", [])
    @property
    def groups(self) -> dict:    return self.get("groups", {})
    @property
    def user_id(self) -> int:    return self.get("user_id", 0)
    @property
    def invites(self) -> list:   return self.get("invites", [])
    @property
    def chat(self) -> list:      return self.get("chat", [])
    @property
    def msg_id(self) -> int:      return self.get("msg_id", 0)
    @property
    def is_group(self) -> bool:   return self.get("is_group", False)

    # ── E2E / prekeys ─────────────────────────────────────────────────────────
    @property
    def prekeys(self) -> list:       return self.get("prekeys", [])
    @property
    def prekey_idx(self) -> int:     return self.get("prekey_idx", -1)
    @property
    def prekey_pub(self) -> str:     return self.get("prekey_pub", "")
    @property
    def prekey_sig(self) -> str:     return self.get("prekey_sig", "")
    @property
    def cert_pem(self) -> str:       return self.get("cert_pem", "")
    @property
    def low_stock(self) -> bool:     return self.get("low_stock", False)
    @property
    def payload_b64(self) -> str:    return self.get("payload", "")
    @property
    def e2e_msg_id(self) -> str:     return self.get("msg_id", "")

    # ── Respostas genéricas do servidor ──────────────────────────────────────

    @classmethod
    def error(cls, reason: str, recipient: str = "") -> "BaseMessage":
        return cls(MsgType.ERROR, {"info": reason}, recipient=recipient)

    def __repr__(self):
        return f"{self.__class__.__name__}(type={self.type}, recipient='{self.recipient}', payload={self.payload})"
