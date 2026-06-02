"""MessagingService — orquestração de alto nível.

Cada método público que comunica com o servidor é bloqueante e pensado para
ser chamado via run_in_executor, i.e., numa thread separada do asyncio loop.
O acesso à UI é serializado pelo ui_lock passado no construtor.

Nota sobre send():
  ServerConnection.send(msg) envia e bloqueia até receber a resposta síncrona.
  Já não existe um receive(TAG_RESPONSE) separado — a resposta é o valor de retorno.
  receive(tag) continua a existir apenas para as filas de push (TAG_E2E, TAG_CHAT, …).
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

import sys, os
_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.Message import Message
from common.MsgType import MsgType
from net.connection import TAG_E2E, TAG_CHAT, TAG_GROUP_EVT
from net.server_conn import ServerConnection, SERVER_CERT_PATH, set_logger_user
from crypto.keystore import Keystore
from crypto.e2e import E2ELayer
from crypto.groups import GroupLayer

_log = logging.getLogger("network")


# ── Tipos devolvidos ao Controller ────────────────────────────────────────────

@dataclass
class ChatSession:
    target:   str
    is_group: bool
    history:  list[dict] = field(default_factory=list)

@dataclass
class SendResult:
    ok:    bool
    text:  str  = ""
    error: str  = ""
    lost:  bool = False


# ── MessagingService ──────────────────────────────────────────────────────────

class MessagingService:

    def __init__(self, conn: ServerConnection, keystore: Keystore,
                 e2e: E2ELayer, groups: GroupLayer, ui_lock: threading.Lock):
        self._conn     = conn
        self._keystore = keystore
        self._e2e      = e2e
        self._groups   = groups
        self._ui_lock  = ui_lock

        # callbacks para o Controller — chamados com ui_lock adquirido
        self.on_message_received:       Callable[[str, str, str, str], None] | None = None
        self.on_group_message_received: Callable[[str, str, str, str], None] | None = None

        self._e2e.on_message    = self._on_e2e_text
        self._groups.on_message = self._on_group_text

    def _start_push_dispatcher(self) -> None:
        """Lança as 3 threads de dispatch de mensagens push. Chamado após login."""
        for tag, handler in (
            (TAG_E2E,       self._dispatch_e2e),
            (TAG_CHAT,      self._dispatch_chat),
            (TAG_GROUP_EVT, self._dispatch_group_evt),
        ):
            threading.Thread(
                target=self._dispatch_loop, args=(tag, handler),
                name=f"Push-{tag}", daemon=True,
            ).start()

    def _dispatch_loop(self, tag: int, handler: Callable) -> None:
        while True:
            msg = self._conn.receive(tag)
            if msg is None:
                return
            try:
                handler(msg)
            except Exception as e:
                _log.error(f"[Push-{tag}] erro: {e}")

    # ── Callbacks de mensagens push → Controller ──────────────────────────────

    def _on_e2e_text(self, sender: str, me: str, text: str, ts: str) -> None:
        if self.on_message_received:
            with self._ui_lock:
                self.on_message_received(sender, me, text, ts)

    def _on_group_text(self, sender: str, group_display: str, text: str, ts: str) -> None:
        if self.on_group_message_received:
            with self._ui_lock:
                self.on_group_message_received(sender, group_display, text, ts)

    def _dispatch_e2e(self, msg: Message) -> None:
        import base64, json as _json
        try:
            raw   = base64.b64decode(msg.payload_b64)
            ptype = _json.loads(raw.decode("utf-8")).get("type", "msg")
        except Exception:
            ptype = "msg"
        if ptype == "sk_dist":
            self._groups.handle_sk_dist(msg.from_ or "?", msg.payload_b64, msg.e2e_msg_id)
        else:
            self._e2e.handle_deliver(msg)

    def _dispatch_chat(self, msg: Message) -> None:
        if msg.type == MsgType.RECEIVE:
            sender    = msg.from_ or "Desconhecido"
            recipient = msg.to    or "Desconhecido"
            text      = msg.text
            timestamp = msg.timestamp or _now()
            if self.on_message_received:
                with self._ui_lock:
                    self.on_message_received(sender, recipient, text, timestamp)
        elif msg.type == MsgType.GROUP_RECEIVE:
            self._groups.handle_receive(msg)

    def _dispatch_group_evt(self, msg: Message) -> None:
        group_name = msg.group_name or ""
        info       = msg.info or "?"
        if msg.type == MsgType.GROUP_MEMBER_LEFT:
            self._groups.handle_member_left(group_name, info)
        elif msg.type == MsgType.GROUP_MEMBER_JOINED:
            self._groups.handle_member_joined(group_name, info)

    # ── Ciclo de vida ─────────────────────────────────────────────────────────

    def connect(self) -> None:
        self._conn.connect()

    def disconnect(self) -> None:
        self._conn.disconnect()
        self._keystore.set_user("")
        self._e2e.reset()
        self._groups.reset()

    def is_connected(self) -> bool:
        return self._conn.is_connected()

    def is_logged_in(self) -> bool:
        return self._conn.dh_shared is not None and self._conn.username is not None

    def username(self) -> str | None:
        return self._conn.username

    # ── Autenticação ──────────────────────────────────────────────────────────

    def login(self, username: str, password: str) -> tuple[bool, str]:
        import common.crypto as crypto
        if self._conn.dh_shared is None:
            return False, "Sem canal seguro."

        self._keystore.set_user(username)
        try:
            privkey = self._keystore.load_client_privkey(password)
        except ValueError:
            self._keystore.set_user("")
            return False, "Password incorreta."
        if not privkey:
            self._keystore.set_user("")
            return False, "Username ou password inválidos."

        sig  = crypto.rsa_sign(privkey, self._conn.gx_bytes + self._conn.gy_bytes)
        resp = self._conn.send(Message.req_login_sts(username, password, sig))

        if resp is None or resp.type != MsgType.OK:
            self._conn.disconnect()
            return False, (resp.info if resp else "") or "Autenticação rejeitada."

        self._conn.username = username
        set_logger_user(username)
        self._e2e.set_privkey(privkey)
        self._e2e.generate_and_upload_prekeys()
        self._start_push_dispatcher()
        return True, resp.info or ""

    def registo(self, username: str, password: str) -> tuple[bool, str]:
        import common.crypto as crypto
        if self._conn.dh_shared is None:
            return False, "Sem canal seguro."

        privkey    = crypto.rsa_generate_keypair()
        pubkey_pem = crypto.rsa_serialize_public(privkey)
        sig        = crypto.rsa_sign(privkey, self._conn.gx_bytes + self._conn.gy_bytes + pubkey_pem)
        resp = self._conn.send(Message.req_registo(username, password, pubkey_pem.decode("utf-8"), sig))
        if resp is None:
            return False, "Resposta do servidor inválida."
        if resp.type == MsgType.OK:
            self._keystore.set_user(username)
            self._keystore.save_client_cert_and_key(resp.get("cert"), privkey, password)
            self._keystore.set_user("")
            return True, resp.info or ""
        return False, resp.reason or "Erro no registo."

    def logout(self) -> tuple[bool, str]:
        try:
            resp = self._conn.send(Message.req_logout())
            if resp and resp.type == MsgType.OK:
                return True, resp.info or ""
            if resp and resp.type == MsgType.ERROR:
                return False, resp.reason or ""
            return False, "Não foi possível receber confirmação do servidor."
        finally:
            self.disconnect()

    # ── Contactos ─────────────────────────────────────────────────────────────

    def add_contact(self, username: str) -> tuple[bool, str]:
        resp = self._conn.send(Message.req_add(username))
        if resp and resp.type == MsgType.OK:
            if resp.cert_pem:
                self._keystore.save_contact_cert(username, resp.cert_pem)
            return True, resp.info or ""
        return False, (resp.reason if resp else "") or ""

    def remove_contact(self, username: str) -> tuple[bool, str]:
        return self._simple(Message.req_remove(username))

    def list_online(self) -> tuple[bool, list, str]:
        resp = self._conn.send(Message.req_list_online())
        if resp and resp.type == MsgType.OK:
            return True, resp.users or [], ""
        return False, [], (resp.reason if resp else "")

    def list_contacts(self) -> tuple[bool, list, str]:
        resp = self._conn.send(Message.req_contacts())
        if resp and resp.type == MsgType.OK:
            return True, resp.users or [], ""
        return False, [], (resp.reason if resp else "")

    # ── Grupos ────────────────────────────────────────────────────────────────

    def create_group(self, group_name: str, members: list[str]) -> tuple[bool, str]:
        resp = self._conn.send(Message.req_create_group(group_name, members))
        if resp and resp.type == MsgType.OK:
            clean = [m.strip() for m in members if m.strip()]
            self._groups.ensure_sender_key_distributed(group_name, clean)
            return True, resp.info or ""
        return False, (resp.reason if resp else "") or ""

    def delete_group(self, group_name: str) -> tuple[bool, str]:
        return self._simple(Message.req_delete_group(group_name))

    def leave_group(self, group_name: str) -> tuple[bool, str]:
        resp = self._conn.send(Message.req_leave_group(group_name))
        if resp and resp.type == MsgType.OK:
            self._groups.discard_sender_key(group_name)
            self._keystore.delete_history(group_name)
            return True, resp.info or ""
        return False, (resp.reason if resp else "") or ""

    def list_groups(self) -> tuple[bool, dict, str]:
        resp = self._conn.send(Message.req_groups())
        if resp and resp.type == MsgType.OK:
            return True, resp.groups or {}, ""
        return False, {}, (resp.reason if resp else "")

    def accept_group(self, group_name: str) -> tuple[bool, str]:
        resp = self._conn.send(Message.req_accept_group(group_name))
        if resp and resp.type == MsgType.OK:
            groups_resp = self._conn.send(Message.req_groups())
            if groups_resp and groups_resp.type == MsgType.OK:
                members = groups_resp.groups.get(group_name, [])
                self._groups.ensure_sender_key_distributed(group_name, members)
            return True, resp.info or ""
        return False, (resp.reason if resp else "") or ""

    def reject_group(self, group_name: str) -> tuple[bool, str]:
        return self._simple(Message.req_reject_group(group_name))

    def list_invites(self) -> tuple[bool, list, str]:
        resp = self._conn.send(Message.req_group_invites())
        if resp and resp.type == MsgType.OK:
            return True, resp.invites or [], ""
        return False, [], (resp.reason if resp else "")

    def invite_member(self, group_name: str, username: str) -> tuple[bool, str]:
        return self._simple(Message.req_add_group_member(group_name, username))

    def kick_member(self, group_name: str, username: str) -> tuple[bool, str]:
        return self._simple(Message.req_kick_group_member(group_name, username))

    # ── Chat ──────────────────────────────────────────────────────────────────

    def open_chat(self, target: str) -> tuple[ChatSession | None, str]:
        resp = self._conn.send(Message.req_chat(target))
        if resp is None:
            return None, "Ligação perdida."
        if resp.type == MsgType.ERROR:
            return None, resp.reason or "Erro ao abrir chat."

        is_group = resp.is_group

        if not is_group:
            ok, err = self._e2e.ensure_session(target)
            if not ok:
                return None, err
        else:
            groups_resp = self._conn.send(Message.req_groups())
            members = []
            if groups_resp and groups_resp.type == MsgType.OK:
                members = [m for m in groups_resp.groups.get(target, [])
                           if m != self._conn.username]
            self._groups.ensure_sender_key_distributed(target, members)

        history = self._keystore.load_history(target)
        return ChatSession(target=target, is_group=is_group, history=history), ""

    def close_chat(self, target: str) -> None:
        try:
            self._conn.send_ack(Message.req_chat_leave(target))
        except OSError:
            pass

    def send_message(self, target: str, is_group: bool,
                     text: str, timestamp: str) -> SendResult:
        me = self._conn.username or ""

        if is_group:
            ok, err = self._groups.send_message(target, text, timestamp)
            if not ok and "perdida" in err:
                return SendResult(ok=False, error=err, lost=True)
            if ok:
                self._keystore.append_history(target, me, f"#{target}", text, timestamp)
                return SendResult(ok=True, text=text)
            return SendResult(ok=False, error=err)

        if self._e2e.has_session(target):
            ok, err = self._e2e.send_message(target, text)
            if not ok and "perdida" in err:
                return SendResult(ok=False, error=err, lost=True)
            if ok:
                self._keystore.append_history(target, me, target, text, timestamp)
                return SendResult(ok=True, text=text)
            return SendResult(ok=False, error=err)

        # fallback plain
        resp = self._conn.send(Message.req_send(me, target, text, timestamp))
        if resp is None:
            return SendResult(ok=False, error="Ligação perdida.", lost=True)
        if resp.type == MsgType.ERROR:
            return SendResult(ok=False, error=resp.reason or "")
        self._keystore.append_history(target, me, target, text, timestamp)
        return SendResult(ok=True, text=text)

    # ── Utilitário ────────────────────────────────────────────────────────────

    def _simple(self, req: Message) -> tuple[bool, str]:
        resp = self._conn.send(req)
        if resp and resp.type == MsgType.OK:
            return True, resp.info or ""
        if resp and resp.type == MsgType.ERROR:
            return False, resp.reason or ""
        return False, ""


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")
