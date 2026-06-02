"""GroupLayer — camada de gestão de sender keys para grupos."""

import logging
import threading
from typing import Callable

import sys, os
_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.Message import Message
from common.MsgType import MsgType
from crypto.e2e_session import GroupSenderKeyManager

_log = logging.getLogger("network")


class GroupLayer:
    """Camada de sender keys para grupos cifrados."""

    def __init__(self, conn, e2e_layer, keystore):
        self._conn     = conn
        self._e2e      = e2e_layer
        self._keystore = keystore
        self._mgr      = GroupSenderKeyManager(keystore)

        self.on_message: Callable[[str, str, str, str], None] | None = None

    def reset(self) -> None:
        self._mgr.reset()

    # ── Sender key própria ────────────────────────────────────────────────────

    def has_sender_key(self, group_name: str) -> bool:
        return self._mgr.has_sender_key(group_name)

    def discard_sender_key(self, group_name: str) -> None:
        self._mgr.discard_sender_key(group_name)

    # ── Distribuição de sender keys ───────────────────────────────────────────

    def ensure_sender_key_distributed(self, group_name: str, members: list[str]) -> None:
        if not self._mgr.has_sender_key(group_name):
            self._mgr.generate_sender_key(group_name)
        for member in members:
            if member != self._conn.username:
                self._distribute_to(group_name, member)

    def _distribute_to(self, group_name: str, member: str) -> bool:
        ok, _ = self._e2e.ensure_session(member)
        if not ok:
            return False
        payload_b64 = self._mgr.build_sk_dist_payload(group_name)
        if payload_b64 is None:
            return False
        msg_id = self._e2e.new_msg_id()
        try:
            ack = self._conn.send(Message.req_e2e_msg(member, msg_id, payload_b64))
            return ack is not None and ack.type == MsgType.OK
        except OSError:
            return False

    # ── Envio / Recepção de mensagens ─────────────────────────────────────────

    def send_message(self, group_name: str, text: str, timestamp: str) -> tuple[bool, str]:
        payload_b64 = self._mgr.encrypt_group_message(group_name, text)
        if payload_b64 is None:
            return False, "Sem sender key — não é possível cifrar. Usa /exit e entra de novo no chat."
        resp = self._conn.send(Message.req_group_send(group_name, payload_b64, timestamp))
        if resp is None:
            return False, "Ligação perdida."
        if resp.type == MsgType.ERROR:
            return False, resp.reason or ""
        return True, ""

    # ── Handlers de mensagens push ────────────────────────────────────────────

    def handle_receive(self, msg: Message) -> None:
        sender      = msg.from_      or "Desconhecido"
        group_name  = msg.group_name or "?"
        payload_b64 = msg.payload_b64
        timestamp   = msg.timestamp  or self._now()
        msg_id      = msg.msg_id

        text = self._mgr.decrypt_group_message(group_name, sender, payload_b64)
        if text is None:
            text = "[mensagem cifrada — sender key não disponível]"

        self._keystore.append_history(group_name, sender, f"#{group_name}", text, timestamp)
        if self.on_message:
            self.on_message(sender, f"#{group_name}", text, timestamp)
        self._conn.send_ack(Message.req_group_ack(group_name, msg_id))

    def handle_sk_dist(self, sender: str, payload_b64: str, msg_id: str) -> None:
        group_name = self._mgr.receive_sk_dist(sender, payload_b64)
        if group_name:
            _log.info(f"[GroupSK] sender key de '{sender}' para grupo '{group_name}' processada")
        self._conn.send_ack(Message.req_e2e_ack(msg_id))

    def handle_member_left(self, group_name: str, left_user: str) -> None:
        if group_name:
            threading.Thread(
                target=self._rotate_sender_key,
                args=(group_name, left_user),
                daemon=True,
            ).start()

    def handle_member_joined(self, group_name: str, new_member: str) -> None:
        if group_name and new_member and new_member != self._conn.username:
            if self._mgr.has_sender_key(group_name):
                threading.Thread(
                    target=self._distribute_to,
                    args=(group_name, new_member),
                    daemon=True,
                ).start()

    def _rotate_sender_key(self, group_name: str, left_user: str) -> None:
        _log.info(f"[GroupSK] '{left_user}' saiu de '{group_name}' — a rodar sender key")
        self._mgr.discard_sender_key(group_name)
        self._mgr.generate_sender_key(group_name)
        groups_resp = self._conn.send(Message.req_groups())
        if groups_resp and groups_resp.type == MsgType.OK:
            for member in groups_resp.groups.get(group_name, []):
                if member != self._conn.username and member != left_user:
                    self._distribute_to(group_name, member)
        _log.info(f"[GroupSK] rotação de sender key de '{group_name}' concluída")

    def _now(self) -> str:
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")
