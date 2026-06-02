import threading
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

import sys
import os

_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.Message import Message
from common.MsgType import MsgType
from net.network import NetworkClient

_log = logging.getLogger("network")


# ── Tipos de resultado devolvidos ao Controller ───────────────────────────────

@dataclass
class ChatSession:
    target:    str
    is_group:  bool
    history:   list[dict] = field(default_factory=list)

@dataclass
class SendResult:
    ok:      bool
    text:    str = ""        # plaintext enviado (para o Controller mostrar na UI)
    error:   str = ""        # mensagem de erro se not ok
    lost:    bool = False    # True se a ligação foi perdida


# ── MessagingService ──────────────────────────────────────────────────────────

class MessagingService:
    """Protocolo de mensagens: sessões E2E, grupos, sender keys, contactos.

    O Controller comunica apenas através de métodos de alto nível e callbacks
    com assinaturas simples (strings). Nunca vê payloads base64, DH, ratchet
    ou tipos de mensagem do protocolo.
    """

    def __init__(self, network: NetworkClient):
        self.network = network

        # callbacks registados pelo Controller
        self.on_message_received:       Callable[[str, str, str, str], None] | None = None
        self.on_group_message_received: Callable[[str, str, str, str], None] | None = None

        # estado interno do protocolo E2E
        self._pending_e2e:    dict[str, list[tuple[str, str]]] = {}
        self._dh_resp_events: dict[str, threading.Event]       = {}

        self.network.on_message_callback = self._on_network_message

    # ── Autenticação ──────────────────────────────────────────────────────────

    def login(self, username: str, password: str) -> tuple[bool, str]:
        response = self.network.login(username, password)
        if response.type == MsgType.OK:
            return True, response.info or ""
        return False, response.reason or "Autenticação rejeitada."

    def registo(self, username: str, password: str) -> tuple[bool, str]:
        msg = self.network.registo(username, password)
        if msg is None:
            return False, "Resposta do servidor inválida."
        if msg.type == MsgType.OK:
            return True, msg.info or ""
        return False, msg.reason or "Erro no registo."

    def logout(self) -> tuple[bool, str]:
        try:
            self.network.send(Message.req_logout())
            msg = self.network.receive()
            if msg and msg.type == MsgType.OK:
                return True, msg.info or ""
            if msg and msg.type == MsgType.ERROR:
                return False, msg.reason or ""
            return False, "Não foi possível receber confirmação do servidor."
        finally:
            self.network.disconnect()

    def connect(self) -> None:
        self.network.connect()

    def disconnect(self) -> None:
        self.network.disconnect()

    def is_logged_in(self) -> bool:
        return self.network.is_logged_in()

    def is_connected(self) -> bool:
        return self.network.transport is not None and self.network.transport.socket is not None

    def username(self) -> str | None:
        return self.network.username

    # ── Contactos ─────────────────────────────────────────────────────────────

    def add_contact(self, username: str) -> tuple[bool, str]:
        self.network.send(Message.req_add(username))
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            if msg.cert_pem:
                self.network.keystore.save_contact_cert(username, msg.cert_pem)
            return True, msg.info or ""
        if msg and msg.type == MsgType.ERROR:
            return False, msg.reason or ""
        return False, ""

    def remove_contact(self, username: str) -> tuple[bool, str]:
        return self._simple_request(Message.req_remove(username))

    def list_online(self) -> tuple[bool, list, str]:
        self.network.send(Message.req_list_online())
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            return True, msg.users or [], ""
        return False, [], (msg.reason if msg else "")

    def list_contacts(self) -> tuple[bool, list, str]:
        self.network.send(Message.req_contacts())
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            return True, msg.users or [], ""
        return False, [], (msg.reason if msg else "")

    # ── Grupos ────────────────────────────────────────────────────────────────

    def create_group(self, group_name: str, members: list[str]) -> tuple[bool, str]:
        self.network.send(Message.req_create_group(group_name, members))
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.network.group_generate_sender_key(group_name)
            for m in members:
                m = m.strip()
                if m and m != self.network.username:
                    self._distribute_sender_key_to(group_name, m)
            return True, msg.info or ""
        if msg and msg.type == MsgType.ERROR:
            return False, msg.reason or ""
        return False, ""

    def delete_group(self, group_name: str) -> tuple[bool, str]:
        return self._simple_request(Message.req_delete_group(group_name))

    def leave_group(self, group_name: str) -> tuple[bool, str]:
        self.network.send(Message.req_leave_group(group_name))
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.network.group_discard_sender_key(group_name)
            self.network.keystore.delete_history(group_name)
            return True, msg.info or ""
        if msg and msg.type == MsgType.ERROR:
            return False, msg.reason or ""
        return False, ""

    def list_groups(self) -> tuple[bool, dict, str]:
        self.network.send(Message.req_groups())
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            return True, msg.groups or {}, ""
        return False, {}, (msg.reason if msg else "")

    def accept_group(self, group_name: str) -> tuple[bool, str]:
        self.network.send(Message.req_accept_group(group_name))
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.network.send(Message.req_groups())
            groups_resp = self.network.receive()
            if groups_resp and groups_resp.type == MsgType.OK:
                self.network.group_generate_sender_key(group_name)
                for member in groups_resp.groups.get(group_name, []):
                    if member != self.network.username:
                        self._distribute_sender_key_to(group_name, member)
            return True, msg.info or ""
        if msg and msg.type == MsgType.ERROR:
            return False, msg.reason or ""
        return False, ""

    def reject_group(self, group_name: str) -> tuple[bool, str]:
        return self._simple_request(Message.req_reject_group(group_name))

    def list_invites(self) -> tuple[bool, list, str]:
        self.network.send(Message.req_group_invites())
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            return True, msg.invites or [], ""
        return False, [], (msg.reason if msg else "")

    def invite_member(self, group_name: str, username: str) -> tuple[bool, str]:
        return self._simple_request(Message.req_add_group_member(group_name, username))

    def kick_member(self, group_name: str, username: str) -> tuple[bool, str]:
        return self._simple_request(Message.req_kick_group_member(group_name, username))

    # ── Chat ──────────────────────────────────────────────────────────────────

    def open_chat(self, target: str) -> tuple[ChatSession | None, str]:
        """Abre sessão de chat: valida no servidor, estabelece E2E/grupo, devolve histórico."""
        self.network.send(Message.req_chat(target))
        response = self.network.receive()
        if response is None:
            return None, "Ligação perdida."
        if response.type == MsgType.ERROR:
            return None, response.reason or "Erro ao abrir chat."

        is_group = response.is_group

        if not is_group:
            ok, err = self._ensure_e2e_session_with_reason(target)
            if not ok:
                return None, err

        if is_group:
            ok, err = self._ensure_group_ready(target)
            if not ok:
                return None, err

        history = self.network.keystore.load_history(target)
        return ChatSession(target=target, is_group=is_group, history=history), ""

    def close_chat(self, target: str) -> None:
        try:
            self.network.send(Message.req_chat_leave(target))
        except OSError:
            pass

    def send_message(self, target: str, is_group: bool, text: str, timestamp: str) -> SendResult:
        """Envia uma mensagem — escolhe automaticamente o modo (grupo/E2E/plain)."""
        me = self.network.username or ""

        if is_group:
            payload_b64 = self.network.group_encrypt_message(target, text)
            if payload_b64 is None:
                return SendResult(ok=False, error="Sem sender key — não é possível cifrar. Usa /exit e entra de novo no chat.")
            self.network.send(Message.req_group_send(target, payload_b64, timestamp))
            resp = self.network.receive()
            if resp is None:
                return SendResult(ok=False, error="Ligação perdida.", lost=True)
            if resp.type == MsgType.ERROR:
                return SendResult(ok=False, error=resp.reason or "")
            self.network.keystore.append_history(target, me, f"#{target}", text, timestamp)
            return SendResult(ok=True, text=text)

        if self.network.has_e2e_session(target):
            payload_b64 = self.network.e2e_send_message(target, text)
            if payload_b64 is None:
                return SendResult(ok=False, error="Falha ao cifrar mensagem.")
            msg_id = self.network.e2e.new_msg_id()
            self.network.send(Message.req_e2e_msg(target, msg_id, payload_b64))
            ack = self.network.receive()
            if ack is None:
                return SendResult(ok=False, error="Ligação perdida.", lost=True)
            if ack.type == MsgType.ERROR:
                return SendResult(ok=False, error=ack.reason or "")
            self.network.keystore.append_history(target, me, target, text, timestamp)
            return SendResult(ok=True, text=text)

        # fallback plain
        self.network.send(Message.req_send(me, target, text, timestamp))
        response = self.network.receive()
        if response is None:
            return SendResult(ok=False, error="Ligação perdida.", lost=True)
        if response.type == MsgType.ERROR:
            return SendResult(ok=False, error=response.reason or "")
        self.network.keystore.append_history(target, me, target, text, timestamp)
        return SendResult(ok=True, text=text)

    # ── Callbacks da receive thread ───────────────────────────────────────────

    def _on_network_message(self, msg: Message) -> None:
        if msg.type == MsgType.E2E_DELIVER:
            self._handle_e2e_deliver(msg)
        elif msg.type == MsgType.RECEIVE:
            self._handle_plain_receive(msg)
        elif msg.type == MsgType.GROUP_RECEIVE:
            self._handle_group_receive(msg)
        elif msg.type == MsgType.GROUP_MEMBER_LEFT:
            group_name = msg.group_name or ""
            left_user  = msg.info or "?"
            if group_name:
                threading.Thread(
                    target=self._rotate_sender_key,
                    args=(group_name, left_user),
                    daemon=True,
                ).start()
        elif msg.type == MsgType.GROUP_MEMBER_JOINED:
            group_name = msg.group_name or ""
            new_member = msg.info or "?"
            if group_name and new_member and new_member != self.network.username:
                if self.network.group_has_sender_key(group_name):
                    threading.Thread(
                        target=self._distribute_sender_key_to,
                        args=(group_name, new_member),
                        daemon=True,
                    ).start()

    def _handle_plain_receive(self, msg: Message) -> None:
        sender    = msg.from_ or "Desconhecido"
        recipient = msg.to    or "Desconhecido"
        text      = msg.text
        timestamp = msg.timestamp or self._now()
        if self.on_message_received:
            self.on_message_received(sender, recipient, text, timestamp)

    def _handle_group_receive(self, msg: Message) -> None:
        sender      = msg.from_      or "Desconhecido"
        group_name  = msg.group_name or "?"
        payload_b64 = msg.payload_b64
        timestamp   = msg.timestamp  or self._now()
        msg_id      = msg.msg_id

        text = self.network.group_decrypt_message(group_name, sender, payload_b64)
        if text is None:
            text = "[mensagem cifrada — sender key não disponível]"

        self.network.keystore.append_history(group_name, sender, f"#{group_name}", text, timestamp)
        if self.on_group_message_received:
            self.on_group_message_received(sender, f"#{group_name}", text, timestamp)
        self.network._send_ack(Message.req_group_ack(group_name, msg_id))

    def _handle_e2e_deliver(self, msg: Message) -> None:
        import base64, json as _json

        sender      = msg.from_ or "Desconhecido"
        msg_id      = msg.e2e_msg_id
        payload_b64 = msg.payload_b64

        try:
            raw   = base64.b64decode(payload_b64)
            inner = _json.loads(raw.decode("utf-8"))
            ptype = inner.get("type", "")
        except Exception:
            ptype = "msg"

        if ptype == "sk_dist":
            group_name = self.network.group_receive_sk_dist(sender, payload_b64)
            if group_name:
                _log.info(f"[GroupSK] sender key de '{sender}' para grupo '{group_name}' processada")
            self.network._send_ack(Message.req_e2e_ack(msg_id))
            return

        if ptype == "dh_init":
            resp_payload = self.network.e2e_receive_dh_init(sender, payload_b64)
            if resp_payload:
                resp_msg_id = self.network.e2e.new_msg_id()
                self.network._send_async(Message.req_e2e_msg(sender, resp_msg_id, resp_payload))
                self._flush_pending_e2e(sender)
            self.network._send_ack(Message.req_e2e_ack(msg_id))
            return

        if ptype == "dh_resp":
            self.network.e2e_receive_dh_resp(sender, payload_b64)
            ev = self._dh_resp_events.get(sender)
            if ev:
                ev.set()
            self.network._send_ack(Message.req_e2e_ack(msg_id))
            return

        if ptype == "init":
            ok = self.network.e2e_receive_init(sender, payload_b64)
            if ok:
                self._flush_pending_e2e(sender)
            self.network._send_ack(Message.req_e2e_ack(msg_id))
            return

        # mensagem normal cifrada E2E
        if not self.network.has_e2e_session(sender):
            self._pending_e2e.setdefault(sender, []).append((msg_id, payload_b64))
            return

        self._flush_pending_e2e(sender)
        self._deliver_e2e_message(sender, msg_id, payload_b64)
        self.network._send_ack(Message.req_e2e_ack(msg_id))

    def _flush_pending_e2e(self, sender: str) -> None:
        for pending_id, pending_payload in self._pending_e2e.pop(sender, []):
            self._deliver_e2e_message(sender, pending_id, pending_payload)
            self.network._send_ack(Message.req_e2e_ack(pending_id))

    def _deliver_e2e_message(self, sender: str, msg_id: str, payload_b64: str) -> None:
        text = self.network.e2e_receive_message(sender, payload_b64)
        if text is None:
            return
        ts = self._now()
        me = self.network.username or "?"
        self.network.keystore.append_history(sender, sender, me, text, ts)
        if self.on_message_received:
            self.on_message_received(sender, me, text, ts)

    # ── Sessão E2E (interno) ──────────────────────────────────────────────────

    def _ensure_e2e_session_with_reason(self, target: str) -> tuple[bool, str]:
        if self.network.has_e2e_session(target):
            return True, ""
        self.network.send(Message.req_prekey_request(target))
        bundle = self.network.receive()
        if bundle is None:
            return False, "Ligação perdida."
        if bundle.type == MsgType.ERROR:
            return False, bundle.reason or "Não foi possível estabelecer sessão E2E."
        if bundle.type == MsgType.ONLINE_BUNDLE:
            ok = self._establish_online(target, bundle.cert_pem)
            return (True, "") if ok else (False, "Falha ao verificar identidade do destinatário.")
        if bundle.type == MsgType.PREKEY_BUNDLE:
            ok = self._establish_offline(target, bundle)
            if not ok:
                return False, "Falha ao verificar identidade do destinatário."
            if bundle.low_stock:
                self.network._generate_and_upload_prekeys()
            return True, ""
        return False, "Resposta inesperada do servidor."

    def _establish_online(self, target: str, cert_pem: str) -> bool:
        dh_payload = self.network.e2e_initiate_online(target, cert_pem)
        if dh_payload is None:
            return False
        ev = threading.Event()
        self._dh_resp_events[target] = ev
        msg_id = self.network.e2e.new_msg_id()
        self.network.send(Message.req_e2e_msg(target, msg_id, dh_payload))
        ack = self.network.receive()
        if ack is None or ack.type == MsgType.ERROR:
            self._dh_resp_events.pop(target, None)
            return False
        if not ev.wait(timeout=10):
            self._dh_resp_events.pop(target, None)
            return False
        self._dh_resp_events.pop(target, None)
        return True

    def _establish_offline(self, target: str, bundle) -> bool:
        init_payload = self.network.e2e_initiate(target, bundle)
        if init_payload is None:
            return False
        msg_id = self.network.e2e.new_msg_id()
        self.network.send(Message.req_e2e_msg(target, msg_id, init_payload))
        ack = self.network.receive()
        if ack is None or ack.type == MsgType.ERROR:
            return False
        return True

    # ── Sender keys de grupo (interno) ───────────────────────────────────────

    def _ensure_group_ready(self, group_name: str) -> tuple[bool, str]:
        self.network.send(Message.req_groups())
        groups_resp = self.network.receive()
        if groups_resp is None:
            return False, "Ligação perdida."
        members = []
        if groups_resp.type == MsgType.OK:
            members = [
                m for m in groups_resp.groups.get(group_name, [])
                if m != self.network.username
            ]
        if not self.network.group_has_sender_key(group_name):
            self.network.group_generate_sender_key(group_name)
        for member in members:
            self._distribute_sender_key_to(group_name, member)
        return True, ""

    def _distribute_sender_key_to(self, group_name: str, member: str) -> bool:
        ok, _ = self._ensure_e2e_session_with_reason(member)
        if not ok:
            return False
        payload_b64 = self.network.group_build_sk_dist_payload(group_name)
        if payload_b64 is None:
            return False
        msg_id = self.network.e2e.new_msg_id()
        try:
            self.network.send(Message.req_e2e_msg(member, msg_id, payload_b64))
            ack = self.network.receive()
            return ack is not None and ack.type == MsgType.OK
        except OSError:
            return False

    def _rotate_sender_key(self, group_name: str, left_user: str) -> None:
        _log.info(f"[GroupSK] '{left_user}' saiu de '{group_name}' — a rodar sender key")
        self.network.group_discard_sender_key(group_name)
        self.network.group_generate_sender_key(group_name)
        self.network.send(Message.req_groups())
        groups_resp = self.network.receive()
        if groups_resp and groups_resp.type == MsgType.OK:
            for member in groups_resp.groups.get(group_name, []):
                if member != self.network.username and member != left_user:
                    self._distribute_sender_key_to(group_name, member)
        _log.info(f"[GroupSK] rotação de sender key de '{group_name}' concluída")

    # ── Utilitário ────────────────────────────────────────────────────────────

    def _simple_request(self, req: Message) -> tuple[bool, str]:
        self.network.send(req)
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            return True, msg.info or ""
        if msg and msg.type == MsgType.ERROR:
            return False, msg.reason or ""
        return False, ""

    def _now(self) -> str:
        return datetime.now().strftime("%H:%M:%S")
